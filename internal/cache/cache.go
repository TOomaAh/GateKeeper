package cache

import (
	"sync"
	"time"

	"github.com/TOomaAh/GateKeeper/internal/domain"
)

const (
	// DefaultCleanupInterval defines the cache cleanup frequency
	DefaultCleanupInterval = 10 * time.Minute
)

// IPCache manages a thread-safe cache of IP information with TTL
type IPCache struct {
	mu      sync.RWMutex
	entries map[string]*domain.IPInfo
	ttl     time.Duration
}

// NewIPCache creates a new cache with a given TTL
func NewIPCache(ttl time.Duration) *IPCache {
	cache := &IPCache{
		entries: make(map[string]*domain.IPInfo),
		ttl:     ttl,
	}

	go cache.cleanupLoop()

	return cache
}

// Get retrieves an entry from the cache if it exists and is not expired
func (c *IPCache) Get(ip string) (*domain.IPInfo, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, exists := c.entries[ip]
	if !exists {
		return nil, false
	}

	if time.Since(entry.Timestamp) > c.ttl {
		return nil, false
	}

	return entry, true
}

// Set adds or updates an entry in the cache
func (c *IPCache) Set(info *domain.IPInfo) {
	c.mu.Lock()
	defer c.mu.Unlock()

	info.Timestamp = time.Now()
	c.entries[info.Address] = info
}

// MarkBlocked marks an IP as blocked in the firewall
func (c *IPCache) MarkBlocked(ip string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if entry, exists := c.entries[ip]; exists {
		entry.BlockedInFW = true
	}
}

// Delete removes an entry from the cache
func (c *IPCache) Delete(ip string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.entries, ip)
}

func (c *IPCache) cleanupLoop() {
	ticker := time.NewTicker(DefaultCleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		c.cleanup()
	}
}

func (c *IPCache) cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	for ip, entry := range c.entries {
		if now.Sub(entry.Timestamp) > c.ttl {
			delete(c.entries, ip)
		}
	}
}
