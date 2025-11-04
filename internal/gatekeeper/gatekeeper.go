package gatekeeper

import (
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/TOomaAh/GateKeeper/internal/abuseip"
	"github.com/TOomaAh/GateKeeper/internal/config"
	"github.com/TOomaAh/GateKeeper/internal/dashboard"
	"github.com/TOomaAh/GateKeeper/internal/database"
	"github.com/TOomaAh/GateKeeper/internal/domain"
	"github.com/TOomaAh/GateKeeper/internal/notification"
	"github.com/TOomaAh/GateKeeper/internal/ratelimit"
	"github.com/TOomaAh/GateKeeper/internal/unifi"
)

const (
	// DefaultCacheTTL is the default cache TTL (1 hour)
	DefaultCacheTTL = 1 * time.Hour
	// DefaultListenAddr is the default listening address
	DefaultListenAddr = ":8888"
	// TarpitDuration is the tarpit duration (1 hour)
	TarpitDuration = 1 * time.Hour
	// TarpitTickInterval is the byte sending interval for tarpit
	TarpitTickInterval = 1 * time.Second
	// DefaultDBPath is the default database path
	DefaultDBPath = "./gatekeeper.db"
)

// GateKeeper manages detection and blocking of direct IP access
type GateKeeper struct {
	config        *config.Configuration
	abuseIpClient *abuseip.Client
	db            *database.IPDatabase
	unifiClients  []*unifi.Client
	notifier      *notification.MultiNotifier
	rateLimiter   *ratelimit.IPRateLimiter
}

// NewGateKeeper creates a new GateKeeper instance
func NewGateKeeper(cfg *config.Configuration) (*GateKeeper, error) {
	abuseClient, err := abuseip.NewClient(cfg.AbuseIP.APIKey)
	if err != nil {
		return nil, err
	}

	var unifiClients []*unifi.Client
	for i := range cfg.Unifi {
		client := unifi.NewClient(&cfg.Unifi[i])
		if err := client.Login(); err != nil {
			log.Printf("Failed to login to UniFi controller %s: %v", cfg.Unifi[i].URL, err)
		} else {
			unifiClients = append(unifiClients, client)
		}
	}

	notifier := notification.NewMultiNotifier(cfg.Notifications.TelegramNotification)

	var rateLimiter *ratelimit.IPRateLimiter
	if cfg.RateLimit.Enabled {
		rateLimiter = ratelimit.NewIPRateLimiter(
			cfg.RateLimit.RequestsPerMinute,
			1*time.Minute,
		)
		log.Printf("Rate limiter enabled: %d requests/minute", cfg.RateLimit.RequestsPerMinute)
	} else {
		rateLimiter = ratelimit.NewDefaultIPRateLimiter()
	}

	dbPath := DefaultDBPath
	if cfg.Database.Path != "" {
		dbPath = cfg.Database.Path
	}

	db, err := database.NewIPDatabase(dbPath, DefaultCacheTTL)
	if err != nil {
		return nil, err
	}

	return &GateKeeper{
		config:        cfg,
		abuseIpClient: abuseClient,
		db:            db,
		unifiClients:  unifiClients,
		notifier:      notifier,
		rateLimiter:   rateLimiter,
	}, nil
}

func (g *GateKeeper) extractClientIP(r *http.Request) string {
	ip := r.Header.Get("X-Forwarded-For")
	if ip == "" {
		ip = r.RemoteAddr
	} else {
		if idx := strings.Index(ip, ","); idx > 0 {
			ip = ip[:idx]
		}
	}

	ip = strings.TrimSpace(ip)

	// Remove port if present
	// IPv4: "192.168.1.1:12345" -> "192.168.1.1"
	// IPv6: "[::1]:12345" -> "::1"
	if strings.Contains(ip, ":") {
		if strings.HasPrefix(ip, "[") {
			if idx := strings.Index(ip, "]"); idx > 0 {
				ip = ip[1:idx]
			}
		} else {
			colonCount := strings.Count(ip, ":")
			if colonCount == 1 {
				ip = strings.Split(ip, ":")[0]
			}
		}
	}

	return ip
}

func (g *GateKeeper) isExcludedIP(ip string) bool {
	return slices.Contains(g.config.ExcludedIPs, ip)
}

func (g *GateKeeper) handler(w http.ResponseWriter, r *http.Request) {
	ip := g.extractClientIP(r)

	if g.isExcludedIP(ip) {
		log.Printf("IP %s is excluded, allowing access", ip)
		w.WriteHeader(http.StatusOK)
		return
	}

	if !g.rateLimiter.Allow(ip) {
		log.Printf("Rate limit exceeded for IP %s", ip)
		http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
		return
	}

	path := r.RequestURI
	log.Printf("Direct IP access detected: IP=%s, Path=%s", ip, path)

	ipInfo := g.getOrCreateIPInfo(ip, path, r)

	g.notifier.Notify(ipInfo)

	if ipInfo.IsHighRisk() {
		log.Printf("Tarpitting IP %s (score: %d)", ip, ipInfo.Score)
		g.tarpit(w, r)
	} else {
		log.Printf("Dropping connection from IP %s (score: %d)", ip, ipInfo.Score)
		g.dropConnection(w)
	}
}

func (g *GateKeeper) getOrCreateIPInfo(ip, path string, r *http.Request) *domain.IPInfo {
	if entry, exists := g.db.Get(ip); exists {
		log.Printf("IP %s found in database (score: %d, blocked: %v)", ip, entry.Score, entry.BlockedInFW)
		entry.Path = path
		return entry
	}

	score, country, err := g.abuseIpClient.Check(ip)
	if err != nil {
		log.Printf("Error checking AbuseIPDB: %v", err)
		score = 0
		country = "Unknown"
	} else {
		log.Printf("AbuseIPDB check: IP=%s, Score=%d, Country=%s", ip, score, country)
	}

	ipInfo := &domain.IPInfo{
		Address:     ip,
		Score:       score,
		Country:     country,
		Path:        path,
		BlockedInFW: false,
		Timestamp:   time.Now(),
	}

	if g.config.Payload.Enabled {
		payloadPath := g.savePayload(ip, r)
		if payloadPath != "" {
			ipInfo.PayloadPath = payloadPath
		}
	}

	if err := g.db.Set(ipInfo); err != nil {
		log.Printf("Failed to save IP to database: %v", err)
	}

	if ipInfo.IsHighRisk() && len(g.unifiClients) > 0 {
		g.blockIPInUniFi(ipInfo)
	}

	return ipInfo
}

func (g *GateKeeper) savePayload(ip string, r *http.Request) string {
	if err := os.MkdirAll(g.config.Payload.Directory, 0755); err != nil {
		log.Printf("Failed to create payload directory: %v", err)
		return ""
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, int64(g.config.Payload.MaxSize)))
	if err != nil {
		log.Printf("Failed to read request body: %v", err)
		return ""
	}

	if len(body) == 0 {
		return ""
	}

	hash := sha256.Sum256(body)
	timestamp := time.Now().Unix()
	filename := fmt.Sprintf("%s_%d_%x.bin", ip, timestamp, hash[:8])
	fullPath := filepath.Join(g.config.Payload.Directory, filename)

	if err := os.WriteFile(fullPath, body, 0644); err != nil {
		log.Printf("Failed to save payload: %v", err)
		return ""
	}

	log.Printf("Saved payload for IP %s: %s (%d bytes)", ip, filename, len(body))
	return fullPath
}

func (g *GateKeeper) blockIPInUniFi(ipInfo *domain.IPInfo) {
	for _, unifiClient := range g.unifiClients {
		if err := unifiClient.AddIPToFirewall(ipInfo.Address); err != nil {
			log.Printf("Failed to block IP %s in UniFi: %v", ipInfo.Address, err)
		} else {
			ipInfo.BlockedInFW = true
			if err := g.db.MarkBlocked(ipInfo.Address); err != nil {
				log.Printf("Failed to mark IP as blocked in database: %v", err)
			}
			log.Printf("IP %s blocked in UniFi firewall", ipInfo.Address)
		}
	}
}

func (g *GateKeeper) tarpit(w http.ResponseWriter, _ *http.Request) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		log.Println("Server doesn't support hijacking, sending normal response")
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}

	conn, _, err := hj.Hijack()
	if err != nil {
		log.Printf("Hijack error: %v", err)
		return
	}

	go func() {
		defer conn.Close()
		ticker := time.NewTicker(TarpitTickInterval)
		defer ticker.Stop()

		timeout := time.After(TarpitDuration)
		for {
			select {
			case <-ticker.C:
				if _, err := conn.Write([]byte{0}); err != nil {
					return
				}
			case <-timeout:
				return
			}
		}
	}()
}

func (g *GateKeeper) dropConnection(w http.ResponseWriter) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		log.Println("Server doesn't support hijacking, sending 403")
		w.WriteHeader(http.StatusForbidden)
		return
	}

	conn, _, err := hj.Hijack()
	if err != nil {
		log.Printf("Hijack error: %v", err)
		w.WriteHeader(http.StatusForbidden)
		return
	}

	conn.Close()
}

// Run starts the HTTP server
func (g *GateKeeper) Run() error {
	// Start dashboard if enabled
	if g.config.Dashboard.Enabled {
		dash := dashboard.NewDashboard(g.config, g.db)
		go func() {
			if err := dash.Run(); err != nil {
				log.Printf("Dashboard error: %v", err)
			}
		}()
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", g.handler)

	log.Printf("GateKeeper listening on %s", DefaultListenAddr)
	log.Printf("Loaded %d UniFi controller(s)", len(g.unifiClients))
	log.Printf("Loaded %d Telegram notification(s)", len(g.config.Notifications.TelegramNotification))

	return http.ListenAndServe(DefaultListenAddr, mux)
}
