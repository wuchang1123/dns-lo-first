package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type ResponseCache struct {
	mu      sync.RWMutex
	path    string
	maxSize int
	items   map[string]ResponseEntry
}

type ResponseEntry struct {
	Msg       []byte
	ExpiresAt time.Time
	StoredAt  time.Time
}

type responseDiskEntry struct {
	Msg                []byte          `json:"msg,omitempty"` // legacy cache format
	Rcode              string          `json:"rcode"`
	Authoritative      bool            `json:"authoritative,omitempty"`
	RecursionAvailable bool            `json:"recursion_available,omitempty"`
	Question           []CacheQuestion `json:"question"`
	Answer             []string        `json:"answer,omitempty"`
	Authority          []string        `json:"authority,omitempty"`
	Additional         []string        `json:"additional,omitempty"`
	ExpiresAt          time.Time       `json:"expires_at"`
	StoredAt           time.Time       `json:"stored_at"`
}

type CacheQuestion struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Class string `json:"class"`
}

func NewResponseCache(dir string, maxSize int) (*ResponseCache, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	c := &ResponseCache{
		path:    filepath.Join(dir, "response_cache.json"),
		maxSize: maxSize,
		items:   map[string]ResponseEntry{},
	}
	_ = c.load()
	return c, nil
}

func ResponseKey(q dns.Question) string {
	return strings.ToLower(strings.TrimSuffix(q.Name, ".")) + "|" + dns.TypeToString[q.Qtype] + "|" + dns.ClassToString[q.Qclass]
}

func (c *ResponseCache) Get(key string) (*dns.Msg, bool, bool) {
	c.mu.RLock()
	e, ok := c.items[key]
	c.mu.RUnlock()
	if !ok {
		return nil, false, false
	}
	var msg dns.Msg
	if err := msg.Unpack(e.Msg); err != nil {
		return nil, false, false
	}
	return &msg, true, time.Now().Before(e.ExpiresAt)
}

func (c *ResponseCache) Put(key string, msg *dns.Msg, ttl time.Duration) {
	if msg == nil {
		return
	}
	cacheMsg := sanitizeMsgForCache(msg)
	packed, err := safePack(cacheMsg)
	if err != nil {
		return
	}
	now := time.Now()
	c.mu.Lock()
	c.items[key] = ResponseEntry{Msg: packed, StoredAt: now, ExpiresAt: now.Add(ttl)}
	c.evictLocked()
	c.mu.Unlock()
	_ = c.save()
}

func (c *ResponseCache) StartJanitor(ctx context.Context, interval, maxAge time.Duration, onClean func(int)) {
	if interval <= 0 || maxAge <= 0 {
		return
	}
	go func() {
		c.cleanOlderThan(maxAge, onClean)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				c.cleanOlderThan(maxAge, onClean)
			case <-ctx.Done():
				return
			}
		}
	}()
}

func (c *ResponseCache) cleanOlderThan(maxAge time.Duration, onClean func(int)) {
	cutoff := time.Now().Add(-maxAge)
	removed := 0
	c.mu.Lock()
	for key, entry := range c.items {
		if !entry.StoredAt.IsZero() && entry.StoredAt.Before(cutoff) {
			delete(c.items, key)
			removed++
		}
	}
	c.mu.Unlock()
	if removed > 0 {
		_ = c.save()
		if onClean != nil {
			onClean(removed)
		}
	}
}

func (c *ResponseCache) evictLocked() {
	if c.maxSize <= 0 || len(c.items) <= c.maxSize {
		return
	}
	var oldestKey string
	var oldest time.Time
	for k, v := range c.items {
		if oldestKey == "" || v.StoredAt.Before(oldest) {
			oldestKey, oldest = k, v.StoredAt
		}
	}
	delete(c.items, oldestKey)
}

func (c *ResponseCache) load() error {
	b, err := os.ReadFile(c.path)
	if err != nil {
		return err
	}
	var diskItems map[string]responseDiskEntry
	if err := json.Unmarshal(b, &diskItems); err != nil {
		return err
	}
	items := make(map[string]ResponseEntry, len(diskItems))
	for key, diskEntry := range diskItems {
		entry, err := diskEntry.toMemoryEntry()
		if err != nil {
			continue
		}
		items[key] = entry
	}
	c.items = items
	return nil
}

func (c *ResponseCache) save() error {
	c.mu.RLock()
	diskItems := make(map[string]responseDiskEntry, len(c.items))
	for key, entry := range c.items {
		diskEntry, err := entry.toDiskEntry()
		if err != nil {
			continue
		}
		diskItems[key] = diskEntry
	}
	b, err := json.MarshalIndent(diskItems, "", "  ")
	c.mu.RUnlock()
	if err != nil {
		return err
	}
	tmp := c.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, c.path)
}

func (e ResponseEntry) toDiskEntry() (responseDiskEntry, error) {
	var msg dns.Msg
	if err := msg.Unpack(e.Msg); err != nil {
		return responseDiskEntry{}, err
	}
	entry := responseDiskEntry{
		Rcode:              dns.RcodeToString[msg.Rcode],
		Authoritative:      msg.Authoritative,
		RecursionAvailable: msg.RecursionAvailable,
		StoredAt:           e.StoredAt,
		ExpiresAt:          e.ExpiresAt,
	}
	for _, q := range msg.Question {
		entry.Question = append(entry.Question, CacheQuestion{
			Name:  q.Name,
			Type:  dns.TypeToString[q.Qtype],
			Class: dns.ClassToString[q.Qclass],
		})
	}
	entry.Answer = rrStrings(msg.Answer)
	entry.Authority = rrStrings(msg.Ns)
	entry.Additional = rrStrings(msg.Extra)
	return entry, nil
}

func (e responseDiskEntry) toMemoryEntry() (ResponseEntry, error) {
	if len(e.Msg) > 0 {
		return ResponseEntry{Msg: e.Msg, StoredAt: e.StoredAt, ExpiresAt: e.ExpiresAt}, nil
	}
	msg := &dns.Msg{}
	msg.Response = true
	msg.Authoritative = e.Authoritative
	msg.RecursionAvailable = e.RecursionAvailable
	msg.Rcode = dns.StringToRcode[e.Rcode]
	for _, q := range e.Question {
		msg.Question = append(msg.Question, dns.Question{
			Name:   q.Name,
			Qtype:  dns.StringToType[q.Type],
			Qclass: dns.StringToClass[q.Class],
		})
	}
	var err error
	if msg.Answer, err = parseRRs(e.Answer); err != nil {
		return ResponseEntry{}, err
	}
	if msg.Ns, err = parseRRs(e.Authority); err != nil {
		return ResponseEntry{}, err
	}
	if msg.Extra, err = parseRRs(e.Additional); err != nil {
		return ResponseEntry{}, err
	}
	packed, err := safePack(msg)
	if err != nil {
		return ResponseEntry{}, err
	}
	return ResponseEntry{Msg: packed, StoredAt: e.StoredAt, ExpiresAt: e.ExpiresAt}, nil
}

func rrStrings(rrs []dns.RR) []string {
	out := make([]string, 0, len(rrs))
	for _, rr := range rrs {
		if rr == nil {
			continue
		}
		if rr.Header().Rrtype == dns.TypeOPT {
			continue
		}
		out = append(out, rr.String())
	}
	return out
}

func parseRRs(lines []string) ([]dns.RR, error) {
	out := make([]dns.RR, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.Contains(line, "OPT PSEUDOSECTION") || strings.HasPrefix(line, ";") {
			continue
		}
		rr, err := dns.NewRR(line)
		if err != nil {
			return nil, err
		}
		if rr == nil {
			continue
		}
		if rr.Header().Rrtype == dns.TypeOPT {
			continue
		}
		out = append(out, rr)
	}
	return out, nil
}

func sanitizeMsgForCache(msg *dns.Msg) *dns.Msg {
	cp := msg.Copy()
	cp.Extra = filterCacheableRRs(cp.Extra)
	return cp
}

func filterCacheableRRs(rrs []dns.RR) []dns.RR {
	out := make([]dns.RR, 0, len(rrs))
	for _, rr := range rrs {
		if rr == nil || rr.Header().Rrtype == dns.TypeOPT {
			continue
		}
		out = append(out, rr)
	}
	return out
}

func safePack(msg *dns.Msg) (packed []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			packed = nil
			err = fmt.Errorf("pack dns msg panic: %v", r)
		}
	}()
	return msg.Pack()
}

type VerdictCache struct {
	mu    sync.RWMutex
	path  string
	items map[string]VerdictEntry
}

type VerdictEntry struct {
	Domain         string    `json:"domain"`
	LocalServer    string    `json:"local_server,omitempty"`
	OverseasServer string    `json:"overseas_server,omitempty"`
	LocalIPs       []string  `json:"local_ips"`
	OverseasIPs    []string  `json:"overseas_ips"`
	Result         string    `json:"result"`
	UpdatedAt      time.Time `json:"updated_at"`
	ExpiresAt      time.Time `json:"expires_at"`
}

func NewVerdictCache(dir string) (*VerdictCache, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	c := &VerdictCache{
		path:  filepath.Join(dir, "verdict_cache.json"),
		items: map[string]VerdictEntry{},
	}
	_ = c.load()
	return c, nil
}

func (c *VerdictCache) Get(domain string) (VerdictEntry, bool) {
	key := strings.ToLower(strings.TrimSuffix(domain, "."))
	c.mu.RLock()
	e, ok := c.items[key]
	c.mu.RUnlock()
	return e, ok && time.Now().Before(e.ExpiresAt)
}

func (c *VerdictCache) Put(domain string, entry VerdictEntry, ttl time.Duration) {
	key := strings.ToLower(strings.TrimSuffix(domain, "."))
	now := time.Now()
	entry.Domain = key
	entry.UpdatedAt = now
	entry.ExpiresAt = now.Add(ttl)
	c.mu.Lock()
	c.items[key] = entry
	c.mu.Unlock()
	_ = c.save()
}

func (c *VerdictCache) load() error {
	b, err := os.ReadFile(c.path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, &c.items)
}

func (c *VerdictCache) save() error {
	c.mu.RLock()
	b, err := json.MarshalIndent(c.items, "", "  ")
	c.mu.RUnlock()
	if err != nil {
		return err
	}
	tmp := c.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, c.path)
}
