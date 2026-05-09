package main

import (
	"container/list"
	"encoding/json"
	"errors"
	"os"
	"sync"
	"time"
)

type resultCache struct {
	mu         sync.Mutex
	enabled    bool
	path       string
	maxEntries int
	ipIdle     time.Duration
	items      map[string]*list.Element
	lru        *list.List
	log        *logger
}

type resultEntry struct {
	Key          string             `json:"key"`
	ResponseHits int                `json:"response_hits"`
	IPs          map[string]*ipStat `json:"ips"`
	LastAccess   time.Time          `json:"last_access"`
}

type ipStat struct {
	Count    int       `json:"count"`
	LastSeen time.Time `json:"last_seen"`
}

func newResultCache(path string, maxEntries int, ipIdle time.Duration, enabled bool, log *logger) (*resultCache, error) {
	c := &resultCache{enabled: enabled, path: path, maxEntries: maxEntries, ipIdle: ipIdle, items: make(map[string]*list.Element), lru: list.New(), log: log}
	if enabled {
		if err := c.load(); err != nil {
			return nil, err
		}
	}
	log.Infof("response result cache loaded enabled=%t entries=%d path=%s", enabled, len(c.items), path)
	return c, nil
}

func (c *resultCache) Exists(key string) bool {
	if !c.enabled {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	elem, ok := c.items[key]
	if !ok {
		return false
	}
	c.lru.MoveToFront(elem)
	entry := elem.Value.(*resultEntry)
	entry.LastAccess = time.Now()
	c.pruneIPs(entry)
	return len(entry.IPs) > 0
}

func (c *resultCache) Put(key string, ips []string) {
	if !c.enabled || len(ips) == 0 {
		return
	}
	now := time.Now()
	c.mu.Lock()
	elem, ok := c.items[key]
	var entry *resultEntry
	if ok {
		entry = elem.Value.(*resultEntry)
		c.lru.MoveToFront(elem)
	} else {
		entry = &resultEntry{Key: key, IPs: make(map[string]*ipStat)}
		c.items[key] = c.lru.PushFront(entry)
	}
	entry.ResponseHits++
	entry.LastAccess = now
	for _, ip := range ips {
		stat := entry.IPs[ip]
		if stat == nil {
			stat = &ipStat{}
			entry.IPs[ip] = stat
		}
		stat.Count++
		stat.LastSeen = now
	}
	c.pruneIPs(entry)
	for c.lru.Len() > c.maxEntries {
		back := c.lru.Back()
		if back == nil {
			break
		}
		old := back.Value.(*resultEntry)
		delete(c.items, old.Key)
		c.lru.Remove(back)
	}
	c.mu.Unlock()
	c.save()
}

func (c *resultCache) Consistent(key string, ips []string) bool {
	if !c.enabled || len(ips) == 0 {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	elem, ok := c.items[key]
	if !ok {
		return false
	}
	c.lru.MoveToFront(elem)
	entry := elem.Value.(*resultEntry)
	entry.LastAccess = time.Now()
	c.pruneIPs(entry)
	cached := make([]string, 0, len(entry.IPs))
	for ip := range entry.IPs {
		cached = append(cached, ip)
	}
	return ipSetsConsistent(ips, cached)
}

func (c *resultCache) pruneIPs(entry *resultEntry) {
	if c.ipIdle <= 0 {
		return
	}
	cutoff := time.Now().Add(-c.ipIdle)
	for ip, stat := range entry.IPs {
		if stat.LastSeen.Before(cutoff) {
			delete(entry.IPs, ip)
		}
	}
}

func (c *resultCache) load() error {
	b, err := os.ReadFile(c.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	var entries []*resultEntry
	if err := json.Unmarshal(b, &entries); err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IPs == nil {
			entry.IPs = make(map[string]*ipStat)
		}
		c.pruneIPs(entry)
		if len(entry.IPs) == 0 {
			continue
		}
		c.items[entry.Key] = c.lru.PushFront(entry)
	}
	return nil
}

func (c *resultCache) save() {
	c.mu.Lock()
	entries := make([]*resultEntry, 0, len(c.items))
	for elem := c.lru.Front(); elem != nil; elem = elem.Next() {
		entries = append(entries, elem.Value.(*resultEntry))
	}
	c.mu.Unlock()
	writeJSON(c.path, entries, c.log)
}
