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
	_, msg, _ := c.GetWithExpiry(key)
	return msg, msg != nil
}

func (c *DNSCache) GetWithExpiry(key string) (bool, *dns.Msg, time.Time) {
	if c.maxSize == 0 {
		return false, nil, time.Time{}
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, exists := c.cache[key]
	if !exists {
		return false, nil, time.Time{}
	}

	isExpired := time.Now().After(entry.expiry)
	return isExpired, entry.response, entry.expiry
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
