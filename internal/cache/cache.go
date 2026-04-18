package cache

import (
	"sync"
	"time"

	"github.com/miekg/dns"
)

type dnsCacheEntry struct {
	response *dns.Msg
	expiry   time.Time
}

type DNSCache struct {
	mu      sync.RWMutex
	cache   map[string]*dnsCacheEntry
	maxSize int
	ttl     time.Duration
}

func NewDNSCache(maxSize int, ttl time.Duration) *DNSCache {
	cache := &DNSCache{
		cache:   make(map[string]*dnsCacheEntry),
		maxSize: maxSize,
		ttl:     ttl,
	}
	go cache.cleanup()
	return cache
}

func (c *DNSCache) Get(key string) (*dns.Msg, bool) {
	if c.maxSize == 0 {
		return nil, false
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, exists := c.cache[key]
	if !exists {
		return nil, false
	}

	if time.Now().After(entry.expiry) {
		return nil, false
	}

	return entry.response, true
}

func (c *DNSCache) Set(key string, response *dns.Msg) {
	if c.maxSize == 0 {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.cache) >= c.maxSize {
		c.evictOldest()
	}

	entry := &dnsCacheEntry{
		response: response.Copy(),
		expiry:   time.Now().Add(c.ttl),
	}
	c.cache[key] = entry
}

func (c *DNSCache) evictOldest() {
	var oldestKey string
	var oldestTime time.Time
	now := time.Now()

	for key, entry := range c.cache {
		if oldestKey == "" || entry.expiry.Before(oldestTime) {
			oldestKey = key
			oldestTime = entry.expiry
		}
	}

	if oldestKey != "" && now.After(oldestTime) {
		delete(c.cache, oldestKey)
	}
}

func (c *DNSCache) cleanup() {
	if c.maxSize == 0 {
		return
	}

	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		c.mu.Lock()
		now := time.Now()
		for key, entry := range c.cache {
			if now.After(entry.expiry) {
				delete(c.cache, key)
			}
		}
		c.mu.Unlock()
	}
}

func (c *DNSCache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.cache)
}

func (c *DNSCache) UpdateResponse(key string, ips []string) bool {
	if c.maxSize == 0 {
		return false
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	entry, exists := c.cache[key]
	if !exists {
		return false
	}

	ipSet := make(map[string]bool)
	for _, ip := range ips {
		ipSet[ip] = true
	}

	var newAns []dns.RR
	for _, rr := range entry.response.Answer {
		if a, ok := rr.(*dns.A); ok {
			if ipSet[a.A.String()] {
				newAns = append(newAns, rr)
			}
		}
	}

	entry.response.Answer = newAns
	entry.expiry = time.Now().Add(c.ttl)
	return true
}
