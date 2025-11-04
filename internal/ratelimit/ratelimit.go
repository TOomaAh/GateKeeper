package ratelimit

import (
	"net/http"
	"sync"
	"time"
)

const (
	// DefaultRate is the number of allowed requests per window
	DefaultRate = 5
	// DefaultWindow is the rate limiting window duration
	DefaultWindow = 1 * time.Minute
	// CleanupInterval is the cleanup frequency for old entries
	CleanupInterval = 5 * time.Minute
)

// IPRateLimiter manages rate limiting per IP
type IPRateLimiter struct {
	mu       sync.RWMutex
	visitors map[string]*visitor
	rate     int
	window   time.Duration
}

type visitor struct {
	count      int
	lastReset  time.Time
	lastAccess time.Time
}

// NewIPRateLimiter creates a new rate limiter
func NewIPRateLimiter(rate int, window time.Duration) *IPRateLimiter {
	limiter := &IPRateLimiter{
		visitors: make(map[string]*visitor),
		rate:     rate,
		window:   window,
	}

	go limiter.cleanupLoop()

	return limiter
}

// NewDefaultIPRateLimiter creates a rate limiter with default values
func NewDefaultIPRateLimiter() *IPRateLimiter {
	return NewIPRateLimiter(DefaultRate, DefaultWindow)
}

// Allow checks if a request is allowed for a given IP
func (rl *IPRateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	v, exists := rl.visitors[ip]

	if !exists {
		rl.visitors[ip] = &visitor{
			count:      1,
			lastReset:  now,
			lastAccess: now,
		}
		return true
	}

	v.lastAccess = now

	if now.Sub(v.lastReset) > rl.window {
		v.count = 1
		v.lastReset = now
		return true
	}

	v.count++
	return v.count <= rl.rate
}

// Reset resets the counter for an IP
func (rl *IPRateLimiter) Reset(ip string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	delete(rl.visitors, ip)
}

func (rl *IPRateLimiter) cleanupLoop() {
	ticker := time.NewTicker(CleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		rl.cleanup()
	}
}

func (rl *IPRateLimiter) cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	for ip, v := range rl.visitors {
		if now.Sub(v.lastAccess) > rl.window*2 {
			delete(rl.visitors, ip)
		}
	}
}

// Middleware creates an HTTP middleware for rate limiting
func (rl *IPRateLimiter) Middleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := extractIP(r)

		if !rl.Allow(ip) {
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}

		next(w, r)
	}
}

func extractIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		for idx := 0; idx < len(xff); idx++ {
			if xff[idx] == ',' {
				return xff[:idx]
			}
		}
		return xff
	}

	for idx := 0; idx < len(r.RemoteAddr); idx++ {
		if r.RemoteAddr[idx] == ':' {
			return r.RemoteAddr[:idx]
		}
	}
	return r.RemoteAddr
}

// Stats contains statistics about the rate limiter
type Stats struct {
	TotalIPs       int
	ActiveLimiters int
}

func (rl *IPRateLimiter) GetStats() Stats {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	now := time.Now()
	activeLimiters := 0

	for _, v := range rl.visitors {
		if now.Sub(v.lastReset) <= rl.window {
			activeLimiters++
		}
	}

	return Stats{
		TotalIPs:       len(rl.visitors),
		ActiveLimiters: activeLimiters,
	}
}
