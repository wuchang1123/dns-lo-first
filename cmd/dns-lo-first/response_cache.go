package main

import (
	"container/list"
	"encoding/json"
	"errors"
	"os"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type responseCache struct {
	mu         sync.Mutex
	enabled    bool
	path       string
	maxEntries int
	staleTTL   time.Duration
	nxdomain   time.Duration
	items      map[string]*list.Element
	lru        *list.List
	log        *logger
}

type responseEntry struct {
	Key        string
	Msg        *dns.Msg
	Upstream   string
	CreatedAt  time.Time
	ExpiresAt  time.Time
	LastAccess time.Time
}

type responseDiskEntry struct {
	Key        string    `json:"key"`
	Rcode      int       `json:"rcode"`
	Answer     []string  `json:"answer"`
	Ns         []string  `json:"ns"`
	Extra      []string  `json:"extra"`
	Upstream   string    `json:"upstream"`
	CreatedAt  time.Time `json:"created_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	LastAccess time.Time `json:"last_access"`
}

func newResponseCache(path string, maxEntries int, staleTTL, nxdomain time.Duration, enabled bool, log *logger) (*responseCache, error) {
	c := &responseCache{
		enabled:    enabled,
		path:       path,
		maxEntries: maxEntries,
		staleTTL:   staleTTL,
		nxdomain:   nxdomain,
		items:      make(map[string]*list.Element),
		lru:        list.New(),
		log:        log,
	}
	if enabled {
		if err := c.load(); err != nil {
			return nil, err
		}
	}
	log.Infof("response cache loaded enabled=%t entries=%d path=%s", enabled, len(c.items), path)
	return c, nil
}

func (c *responseCache) Get(key string, req *dns.Msg) (*dns.Msg, bool, bool) {
	if !c.enabled {
		return nil, false, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	elem, ok := c.items[key]
	if !ok {
		return nil, false, false
	}
	c.lru.MoveToFront(elem)
	entry := elem.Value.(*responseEntry)
	entry.LastAccess = time.Now()
	expired := time.Now().After(entry.ExpiresAt)
	msg := entry.Msg.Copy()
	msg.SetReply(req)
	if expired {
		setAllTTL(msg, uint32(c.staleTTL.Seconds()))
	} else {
		ttl := uint32(time.Until(entry.ExpiresAt).Seconds())
		if ttl == 0 {
			ttl = 1
		}
		setAllTTL(msg, ttl)
	}
	return msg, expired, true
}

func (c *responseCache) Put(key string, req, msg *dns.Msg, upstream string) bool {
	if !c.enabled || !cacheableBasic(msg) {
		return false
	}
	now := time.Now()
	ttl := c.ttl(msg)
	entry := &responseEntry{
		Key:        key,
		Msg:        msg.Copy(),
		Upstream:   upstream,
		CreatedAt:  now,
		ExpiresAt:  now.Add(ttl),
		LastAccess: now,
	}
	c.mu.Lock()
	if elem, ok := c.items[key]; ok {
		elem.Value = entry
		c.lru.MoveToFront(elem)
	} else {
		c.items[key] = c.lru.PushFront(entry)
	}
	for c.lru.Len() > c.maxEntries {
		back := c.lru.Back()
		if back == nil {
			break
		}
		old := back.Value.(*responseEntry)
		delete(c.items, old.Key)
		c.lru.Remove(back)
	}
	c.mu.Unlock()
	c.save()
	return true
}

func (c *responseCache) ttl(msg *dns.Msg) time.Duration {
	if msg.Rcode == dns.RcodeNameError {
		return c.nxdomain
	}
	minTTL := uint32(300)
	found := false
	for _, rr := range msg.Answer {
		if rr.Header().Ttl < minTTL {
			minTTL = rr.Header().Ttl
		}
		found = true
	}
	if !found || minTTL == 0 {
		minTTL = 30
	}
	return time.Duration(minTTL) * time.Second
}

func (c *responseCache) load() error {
	b, err := os.ReadFile(c.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	var disk []responseDiskEntry
	if err := json.Unmarshal(b, &disk); err != nil {
		return err
	}
	for _, de := range disk {
		msg := new(dns.Msg)
		msg.Rcode = de.Rcode
		for _, raw := range de.Answer {
			rr, err := dns.NewRR(raw)
			if err == nil {
				msg.Answer = append(msg.Answer, rr)
			}
		}
		for _, raw := range de.Ns {
			rr, err := dns.NewRR(raw)
			if err == nil {
				msg.Ns = append(msg.Ns, rr)
			}
		}
		for _, raw := range de.Extra {
			rr, err := dns.NewRR(raw)
			if err == nil {
				msg.Extra = append(msg.Extra, rr)
			}
		}
		entry := &responseEntry{Key: de.Key, Msg: msg, Upstream: de.Upstream, CreatedAt: de.CreatedAt, ExpiresAt: de.ExpiresAt, LastAccess: de.LastAccess}
		c.items[de.Key] = c.lru.PushFront(entry)
	}
	return nil
}

func (c *responseCache) save() {
	c.mu.Lock()
	disk := make([]responseDiskEntry, 0, len(c.items))
	for elem := c.lru.Front(); elem != nil; elem = elem.Next() {
		entry := elem.Value.(*responseEntry)
		disk = append(disk, responseDiskEntry{
			Key:        entry.Key,
			Rcode:      entry.Msg.Rcode,
			Answer:     rrStrings(entry.Msg.Answer),
			Ns:         rrStrings(entry.Msg.Ns),
			Extra:      rrStrings(entry.Msg.Extra),
			Upstream:   entry.Upstream,
			CreatedAt:  entry.CreatedAt,
			ExpiresAt:  entry.ExpiresAt,
			LastAccess: entry.LastAccess,
		})
	}
	c.mu.Unlock()
	writeJSON(c.path, disk, c.log)
}
