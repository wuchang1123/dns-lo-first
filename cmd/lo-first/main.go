package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/idna"
	"gopkg.in/yaml.v3"
)

const (
	groupLocal    = "local"
	groupOverseas = "overseas"
	routeLocal    = "local"
	routeOverseas = "overseas"
	routeDefault  = "default"
)

func main() {
	configPath := flag.String("config", "config.yaml", "path to config.yaml")
	flag.Parse()

	cfg, err := loadConfig(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	appLog, err := newAppLogger(cfg.Server.LogPath, cfg.Server.LogLevel, cfg.Server.LogTimezone)
	if err != nil {
		log.Fatalf("create logger: %v", err)
	}
	defer appLog.Close()
	appLog.Infof("dns-lo-first starting config=%s base_dir=%s listen=%s", *configPath, cfg.BaseDir, cfg.Server.Listen)
	appLog.Infof("paths log=%s cache=%s local_domains=%s asn=%s", cfg.Server.LogPath, cfg.Server.CachePath, cfg.LocalDomains.FilePath, cfg.ASN.FilePath)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	srv, err := newDNSServer(cfg, appLog)
	if err != nil {
		appLog.Fatalf("create dns server: %v", err)
	}
	srv.startJanitors(ctx)
	srv.startLocalDomainUpdater(ctx)
	appLog.Infof("dns-lo-first startup complete")

	if err := srv.listenAndServe(ctx); err != nil {
		appLog.Fatalf("server stopped: %v", err)
	}
}

type Config struct {
	BaseDir      string       `yaml:"base_dir"`
	Server       ServerConfig `yaml:"server"`
	Cache        CacheConfig  `yaml:"cache"`
	BootstrapDNS []string     `yaml:"bootstrap_dns"`
	Upstream     UpstreamConf `yaml:"upstream"`
	LocalDomains LocalDomains `yaml:"local_domains"`
	ASN          ASNConfig    `yaml:"asn"`
	Comparison   CompareConf  `yaml:"comparison"`
	configDir    string
}

type ServerConfig struct {
	Listen                 string `yaml:"listen"`
	DomainTTL              uint32 `yaml:"domain_ttl"`
	ConcurrentTimeout      int    `yaml:"concurrent_timeout"`
	UpstreamTimeout        int    `yaml:"upstream_timeout"`
	UpstreamFreezeDuration int    `yaml:"upstream_freeze_duration"`
	LogPath                string `yaml:"log_path"`
	CachePath              string `yaml:"cache_path"`
	LogTimezone            string `yaml:"log_timezone"`
	LogLevel               string `yaml:"log_level"`
}

type CacheConfig struct {
	Response   ResponseCacheConfig   `yaml:"response"`
	Comparison ComparisonCacheConfig `yaml:"comparison"`
	SuspectTTL uint32                `yaml:"suspect_ttl"`
}

type ResponseCacheConfig struct {
	Enabled           bool   `yaml:"enabled"`
	MemorySize        int    `yaml:"memory_size"`
	StaleTTL          uint32 `yaml:"stale_ttl"`
	CleanupAfterHours int    `yaml:"cleanup_after_hours"`
}

type ComparisonCacheConfig struct {
	Enabled  bool `yaml:"enabled"`
	TTLHours int  `yaml:"ttl_hours"`
}

type UpstreamConf struct {
	Servers          UpstreamServers `yaml:"servers"`
	Scoring          ScoringConfig   `yaml:"scoring"`
	LocalOnly        []string        `yaml:"local_only"`
	OverseasOnly     []string        `yaml:"overseas_only"`
	EDNSClientSubnet ECSConfig       `yaml:"edns_client_subnet"`
}

type UpstreamServers struct {
	Local    []string `yaml:"local"`
	Overseas []string `yaml:"overseas"`
}

type ScoringConfig struct {
	Enabled                     bool   `yaml:"enabled"`
	InitialScore                int    `yaml:"initial_score"`
	LatencyWindow               int    `yaml:"latency_window"`
	SuccessWeight               int    `yaml:"success_weight"`
	FailurePenalty              int    `yaml:"failure_penalty"`
	TimeoutPenalty              int    `yaml:"timeout_penalty"`
	ConsecutiveFailurePenalty   int    `yaml:"consecutive_failure_penalty"`
	LatencyPenaltyPer100ms      int    `yaml:"latency_penalty_per_100ms"`
	MinScore                    int    `yaml:"min_score"`
	MaxScore                    int    `yaml:"max_score"`
	LowScoreProbeInterval       string `yaml:"low_score_probe_interval"`
	SameScoreRandom             bool   `yaml:"same_score_random"`
	lowScoreProbeIntervalParsed time.Duration
}

type ECSConfig struct {
	Enabled bool   `yaml:"enabled"`
	IPv4    string `yaml:"ipv4"`
	IPv6    string `yaml:"ipv6"`
}

type LocalDomains struct {
	SourceURL           string `yaml:"source_url"`
	FilePath            string `yaml:"file_path"`
	UpdateIntervalHours int    `yaml:"update_interval_hours"`
}

type ASNConfig struct {
	Enabled  bool   `yaml:"enabled"`
	FilePath string `yaml:"file_path"`
}

type CompareConf struct {
	AllowSame24AsWeakMatch bool `yaml:"allow_same_24_as_weak_match"`
	AllowSame16Match       bool `yaml:"allow_same_16_match"`
}

func loadConfig(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return nil, err
	}
	cfg.configDir = filepath.Dir(path)
	if cfg.BaseDir == "" {
		cfg.BaseDir = cfg.configDir
	}
	cfg.applyDefaults()
	cfg.normalizePaths()
	if len(cfg.Upstream.Servers.Local) == 0 && len(cfg.Upstream.Servers.Overseas) == 0 {
		return nil, errors.New("no upstream servers configured")
	}
	return &cfg, nil
}

func (c *Config) applyDefaults() {
	if c.Server.Listen == "" {
		c.Server.Listen = ":5355"
	}
	if c.Server.DomainTTL == 0 {
		c.Server.DomainTTL = 60
	}
	if c.Server.ConcurrentTimeout <= 0 {
		c.Server.ConcurrentTimeout = 6
	}
	if c.Server.UpstreamTimeout <= 0 {
		c.Server.UpstreamTimeout = 3
	}
	if c.Server.UpstreamFreezeDuration <= 0 {
		c.Server.UpstreamFreezeDuration = 60
	}
	if c.Server.LogPath == "" {
		c.Server.LogPath = "./log"
	}
	if c.Server.CachePath == "" {
		c.Server.CachePath = "./cache"
	}
	if c.Server.LogTimezone == "" {
		c.Server.LogTimezone = "Asia/Shanghai"
	}
	if c.Server.LogLevel == "" {
		c.Server.LogLevel = "info"
	}
	if c.Cache.Response.MemorySize <= 0 {
		c.Cache.Response.MemorySize = 10000
	}
	if c.Cache.Response.StaleTTL == 0 {
		c.Cache.Response.StaleTTL = 3
	}
	if c.Cache.Response.CleanupAfterHours <= 0 {
		c.Cache.Response.CleanupAfterHours = 48
	}
	if c.Cache.Comparison.TTLHours <= 0 {
		c.Cache.Comparison.TTLHours = 168
	}
	if c.Cache.SuspectTTL == 0 {
		c.Cache.SuspectTTL = 30
	}
	if len(c.BootstrapDNS) == 0 {
		c.BootstrapDNS = []string{"223.5.5.5:53", "8.8.8.8:53", "1.1.1.1:53"}
	}
	if c.LocalDomains.UpdateIntervalHours <= 0 {
		c.LocalDomains.UpdateIntervalHours = 24
	}
	if c.ASN.FilePath == "" {
		c.ASN.FilePath = "./data/domain_asn.yaml"
	}
	c.Upstream.Scoring.applyDefaults()
}

func (s *ScoringConfig) applyDefaults() {
	if s.InitialScore == 0 {
		s.InitialScore = 100
	}
	if s.LatencyWindow <= 0 {
		s.LatencyWindow = 20
	}
	if s.SuccessWeight == 0 {
		s.SuccessWeight = 10
	}
	if s.FailurePenalty == 0 {
		s.FailurePenalty = 25
	}
	if s.TimeoutPenalty == 0 {
		s.TimeoutPenalty = 50
	}
	if s.ConsecutiveFailurePenalty == 0 {
		s.ConsecutiveFailurePenalty = 15
	}
	if s.LatencyPenaltyPer100ms == 0 {
		s.LatencyPenaltyPer100ms = 2
	}
	if s.MaxScore == 0 {
		s.MaxScore = 1000
	}
	if s.LowScoreProbeInterval == "" {
		s.LowScoreProbeInterval = "1h"
	}
	d, err := time.ParseDuration(s.LowScoreProbeInterval)
	if err != nil || d <= 0 {
		d = time.Hour
	}
	s.lowScoreProbeIntervalParsed = d
}

func (c *Config) normalizePaths() {
	c.BaseDir = c.abs(c.BaseDir)
	c.Server.LogPath = c.absWithFallback(c.Server.LogPath)
	c.Server.CachePath = c.absWithFallback(c.Server.CachePath)
	c.LocalDomains.FilePath = c.absWithFallback(c.LocalDomains.FilePath)
	c.ASN.FilePath = c.absWithFallback(c.ASN.FilePath)
}

func (c *Config) abs(p string) string {
	if p == "" {
		return ""
	}
	if filepath.IsAbs(p) {
		return p
	}
	return filepath.Clean(filepath.Join(c.configDir, p))
}

func (c *Config) absWithFallback(p string) string {
	if p == "" {
		return ""
	}
	if filepath.IsAbs(p) {
		if _, err := os.Stat(p); err == nil {
			return p
		}
		const prefix = "/etc/dns-lo-first/"
		if strings.HasPrefix(p, prefix) {
			local := filepath.Join(c.configDir, strings.TrimPrefix(p, prefix))
			if _, err := os.Stat(local); err == nil {
				return local
			}
		}
		return p
	}
	return filepath.Clean(filepath.Join(c.BaseDir, p))
}

type appLogger struct {
	mu       sync.Mutex
	level    int
	tz       *time.Location
	base     *os.File
	query    *os.File
	baseLog  *log.Logger
	queryLog *log.Logger
}

const (
	levelDebug = iota
	levelInfo
	levelWarn
	levelError
	levelFatal
)

func newAppLogger(dir, lvl, tz string) (*appLogger, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	loc, err := time.LoadLocation(tz)
	if err != nil {
		loc = time.Local
	}
	base, err := os.OpenFile(filepath.Join(dir, "dns-lo-first.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}
	query, err := os.OpenFile(filepath.Join(dir, "query.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		_ = base.Close()
		return nil, err
	}
	return &appLogger{
		level:    parseLevel(lvl),
		tz:       loc,
		base:     base,
		query:    query,
		baseLog:  log.New(io.MultiWriter(os.Stdout, base), "", 0),
		queryLog: log.New(query, "", 0),
	}, nil
}

func parseLevel(s string) int {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return levelDebug
	case "warn":
		return levelWarn
	case "error":
		return levelError
	case "fatal":
		return levelFatal
	default:
		return levelInfo
	}
}

func (l *appLogger) Close() {
	_ = l.base.Close()
	_ = l.query.Close()
}

func (l *appLogger) logf(level int, name, format string, args ...any) {
	if level < l.level {
		return
	}
	line := fmt.Sprintf("%s %-5s %s", l.formatTime(time.Now()), strings.ToUpper(name), fmt.Sprintf(format, args...))
	l.mu.Lock()
	defer l.mu.Unlock()
	l.baseLog.Println(line)
}

func (l *appLogger) Debugf(format string, args ...any) { l.logf(levelDebug, "debug", format, args...) }
func (l *appLogger) Infof(format string, args ...any)  { l.logf(levelInfo, "info", format, args...) }
func (l *appLogger) Warnf(format string, args ...any)  { l.logf(levelWarn, "warn", format, args...) }
func (l *appLogger) Errorf(format string, args ...any) { l.logf(levelError, "error", format, args...) }
func (l *appLogger) Fatalf(format string, args ...any) {
	l.logf(levelFatal, "fatal", format, args...)
	os.Exit(1)
}
func (l *appLogger) Queryf(format string, args ...any) {
	line := fmt.Sprintf("%s %s", l.formatTime(time.Now()), fmt.Sprintf(format, args...))
	l.mu.Lock()
	defer l.mu.Unlock()
	l.queryLog.Println(line)
}
func (l *appLogger) formatTime(t time.Time) string  { return t.In(l.tz).Format("06-01-02 15:04:05.000") }
func (l *appLogger) formatClock(t time.Time) string { return t.In(l.tz).Format("15:04:05.000") }

func (l *appLogger) startJanitor(ctx context.Context, dir string, maxAge time.Duration) {
	go func() {
		ticker := time.NewTicker(time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				cleanOldFiles(dir, maxAge, l)
			case <-ctx.Done():
				return
			}
		}
	}()
}

func cleanOldFiles(dir string, maxAge time.Duration, l *appLogger) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	cutoff := time.Now().Add(-maxAge)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err == nil && info.ModTime().Before(cutoff) {
			if err := os.Remove(filepath.Join(dir, e.Name())); err == nil {
				l.Infof("removed old log file: %s", e.Name())
			}
		}
	}
}

type Matcher struct {
	apex   map[string]struct{}
	strict map[string]struct{}
}

func newMatcher(patterns []string) *Matcher {
	m := &Matcher{apex: map[string]struct{}{}, strict: map[string]struct{}{}}
	for _, p := range patterns {
		m.Add(p)
	}
	return m
}

func (m *Matcher) Add(pattern string) {
	p := normalizeDomain(pattern)
	if p == "" {
		return
	}
	if strings.HasPrefix(p, "*.") {
		p = strings.TrimPrefix(p, "*.")
		if p != "" {
			m.strict[p] = struct{}{}
		}
		return
	}
	m.apex[p] = struct{}{}
}

func (m *Matcher) Match(name string) bool {
	n := normalizeDomain(name)
	if n == "" {
		return false
	}
	if _, ok := m.apex[n]; ok {
		return true
	}
	parts := strings.Split(n, ".")
	for i := 1; i < len(parts); i++ {
		suffix := strings.Join(parts[i:], ".")
		if _, ok := m.apex[suffix]; ok {
			return true
		}
		if _, ok := m.strict[suffix]; ok {
			return true
		}
	}
	return false
}

func normalizeDomain(name string) string {
	n := strings.TrimSpace(strings.ToLower(name))
	n = strings.TrimSuffix(n, ".")
	if n == "" {
		return ""
	}
	if ascii, err := idna.Lookup.ToASCII(n); err == nil {
		n = ascii
	}
	return n
}

func loadDomainFile(path string) ([]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []string
	for _, line := range strings.Split(string(b), "\n") {
		out = append(out, parseDomainLine(line)...)
	}
	return out, nil
}

func parseDomainLine(line string) []string {
	s := strings.TrimSpace(line)
	if s == "" || strings.HasPrefix(s, "#") {
		return nil
	}
	if idx := strings.Index(s, "#"); idx >= 0 {
		s = strings.TrimSpace(s[:idx])
	}
	if strings.HasPrefix(s, "server=/") || strings.HasPrefix(s, "ipset=/") || strings.HasPrefix(s, "nftset=/") {
		parts := strings.Split(s, "/")
		if len(parts) < 3 {
			return nil
		}
		var domains []string
		for _, part := range parts[1 : len(parts)-1] {
			if d := normalizeDomain(strings.TrimPrefix(part, ".")); d != "" {
				domains = append(domains, d)
			}
		}
		return domains
	}
	if d := normalizeDomain(s); d != "" {
		return []string{d}
	}
	return nil
}

type asnFile struct {
	Version  int                    `yaml:"version"`
	Orgs     map[string]asnOrg      `yaml:"orgs"`
	Suffixes []asnSuffixAssociation `yaml:"suffixes"`
}

type asnOrg struct {
	Prefixes []string `yaml:"prefixes"`
}

type asnSuffixAssociation struct {
	Suffix string   `yaml:"suffix"`
	Org    string   `yaml:"org"`
	Orgs   []string `yaml:"orgs"`
}

type asnDB struct {
	orgs     map[string][]*net.IPNet
	suffixes []asnSuffixRule
}

type asnSuffixRule struct {
	suffix string
	orgs   []string
}

func loadASN(path string) (*asnDB, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f asnFile
	if err := yaml.Unmarshal(b, &f); err != nil {
		return nil, err
	}
	db := &asnDB{orgs: map[string][]*net.IPNet{}}
	for name, org := range f.Orgs {
		key := strings.ToLower(strings.TrimSpace(name))
		for _, p := range org.Prefixes {
			if _, n, err := net.ParseCIDR(strings.TrimSpace(p)); err == nil && n.IP.To4() != nil {
				db.orgs[key] = append(db.orgs[key], n)
			}
		}
	}
	for _, assoc := range f.Suffixes {
		suffix := normalizeDomain(assoc.Suffix)
		if suffix == "" {
			continue
		}
		orgs := append([]string{}, assoc.Orgs...)
		if assoc.Org != "" {
			orgs = append(orgs, assoc.Org)
		}
		var normalized []string
		for _, org := range orgs {
			if o := strings.ToLower(strings.TrimSpace(org)); o != "" {
				normalized = append(normalized, o)
			}
		}
		if len(normalized) > 0 {
			db.suffixes = append(db.suffixes, asnSuffixRule{suffix: suffix, orgs: normalized})
		}
	}
	return db, nil
}

func (db *asnDB) check(names []string, ips []net.IP) (known bool, good []net.IP) {
	if db == nil {
		return false, nil
	}
	orgs := map[string]struct{}{}
	for _, name := range names {
		for _, org := range db.matchOrgs(name) {
			orgs[org] = struct{}{}
		}
	}
	if len(orgs) == 0 {
		return false, nil
	}
	seen := map[string]struct{}{}
	for _, ip := range ips {
		ip4 := ip.To4()
		if ip4 == nil {
			continue
		}
		for org := range orgs {
			for _, n := range db.orgs[org] {
				if n.Contains(ip4) {
					if _, ok := seen[ip4.String()]; !ok {
						seen[ip4.String()] = struct{}{}
						good = append(good, ip4)
					}
				}
			}
		}
	}
	return true, good
}

func (db *asnDB) matchOrgs(name string) []string {
	n := normalizeDomain(name)
	var best int
	var out []string
	for _, r := range db.suffixes {
		if n == r.suffix || strings.HasSuffix(n, "."+r.suffix) {
			if len(r.suffix) > best {
				best = len(r.suffix)
				out = append([]string{}, r.orgs...)
			}
		}
	}
	return out
}

type responseCache struct {
	mu      sync.RWMutex
	path    string
	maxSize int
	items   map[string]responseEntry
	enabled bool
}

type responseEntry struct {
	Msg                []byte
	UpstreamServer     string
	UpstreamGroup      string
	ASNPassed          bool
	StoredAt           time.Time
	ExpiresAt          time.Time
	Rcode              int
	Authoritative      bool
	RecursionAvailable bool
	Question           []cacheQuestion
	Answer             []string
	Authority          []string
	Additional         []string
}

type responseDiskEntry struct {
	Msg                []byte          `json:"msg,omitempty"` // legacy only; new writes omit packed DNS messages.
	UpstreamServer     string          `json:"upstream_server,omitempty"`
	UpstreamGroup      string          `json:"upstream_group,omitempty"`
	ASNPassed          bool            `json:"asn_passed,omitempty"`
	StoredAt           time.Time       `json:"stored_at"`
	ExpiresAt          time.Time       `json:"expires_at"`
	Rcode              string          `json:"rcode"`
	Authoritative      bool            `json:"authoritative,omitempty"`
	RecursionAvailable bool            `json:"recursion_available,omitempty"`
	Question           []cacheQuestion `json:"question,omitempty"`
	Answer             []string        `json:"answer,omitempty"`
	Authority          []string        `json:"authority,omitempty"`
	Additional         []string        `json:"additional,omitempty"`
}

type cacheQuestion struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Class string `json:"class"`
}

func newResponseCache(dir string, maxSize int, enabled bool) (*responseCache, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	c := &responseCache{path: filepath.Join(dir, "response_cache.json"), maxSize: maxSize, items: map[string]responseEntry{}, enabled: enabled}
	_ = c.load()
	return c, nil
}

func (c *responseCache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.items)
}

func responseKey(q dns.Question) string {
	return normalizeDomain(q.Name) + "|" + dns.TypeToString[q.Qtype] + "|" + dns.ClassToString[q.Qclass]
}

func (c *responseCache) Get(key string) (*dns.Msg, responseEntry, bool, bool) {
	if !c.enabled {
		return nil, responseEntry{}, false, false
	}
	c.mu.RLock()
	e, ok := c.items[key]
	c.mu.RUnlock()
	if !ok {
		return nil, responseEntry{}, false, false
	}
	var msg dns.Msg
	if err := msg.Unpack(e.Msg); err != nil {
		return nil, responseEntry{}, false, false
	}
	return &msg, e, true, time.Now().Before(e.ExpiresAt)
}

func (c *responseCache) Put(key string, msg *dns.Msg, ttl time.Duration, upstream, group string, asnPassed bool) {
	if !c.enabled || msg == nil {
		return
	}
	cp := msg.Copy()
	cp.Extra = filterCacheableRRs(cp.Extra)
	packed, err := cp.Pack()
	if err != nil {
		return
	}
	now := time.Now()
	e := responseEntry{
		Msg: packed, UpstreamServer: upstream, UpstreamGroup: group, ASNPassed: asnPassed,
		StoredAt: now, ExpiresAt: now.Add(ttl), Rcode: cp.Rcode,
		Authoritative: cp.Authoritative, RecursionAvailable: cp.RecursionAvailable,
		Question: questionStrings(cp.Question), Answer: rrStrings(cp.Answer),
		Authority: rrStrings(cp.Ns), Additional: rrStrings(cp.Extra),
	}
	c.mu.Lock()
	c.items[key] = e
	c.evictLocked()
	c.mu.Unlock()
	_ = c.save()
}

func (c *responseCache) evictLocked() {
	if c.maxSize <= 0 || len(c.items) <= c.maxSize {
		return
	}
	var oldestKey string
	var oldest time.Time
	for key, entry := range c.items {
		if oldestKey == "" || entry.StoredAt.Before(oldest) {
			oldestKey, oldest = key, entry.StoredAt
		}
	}
	delete(c.items, oldestKey)
}

func (c *responseCache) cleanOlderThan(maxAge time.Duration) int {
	cutoff := time.Now().Add(-maxAge)
	removed := 0
	c.mu.Lock()
	for key, entry := range c.items {
		if entry.StoredAt.Before(cutoff) {
			delete(c.items, key)
			removed++
		}
	}
	c.mu.Unlock()
	if removed > 0 {
		_ = c.save()
	}
	return removed
}

func (c *responseCache) load() error {
	b, err := os.ReadFile(c.path)
	if err != nil {
		return err
	}
	var diskItems map[string]responseDiskEntry
	if err := json.Unmarshal(b, &diskItems); err != nil {
		return err
	}
	items := make(map[string]responseEntry, len(diskItems))
	for key, disk := range diskItems {
		entry, err := disk.toMemoryEntry()
		if err != nil {
			continue
		}
		items[key] = entry
	}
	c.items = items
	return nil
}

func (c *responseCache) save() error {
	c.mu.RLock()
	diskItems := make(map[string]responseDiskEntry, len(c.items))
	for key, entry := range c.items {
		diskItems[key] = entry.toDiskEntry()
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

func (e responseEntry) toDiskEntry() responseDiskEntry {
	return responseDiskEntry{
		UpstreamServer: e.UpstreamServer, UpstreamGroup: e.UpstreamGroup, ASNPassed: e.ASNPassed,
		StoredAt: e.StoredAt, ExpiresAt: e.ExpiresAt, Rcode: dns.RcodeToString[e.Rcode],
		Authoritative: e.Authoritative, RecursionAvailable: e.RecursionAvailable,
		Question: e.Question, Answer: e.Answer, Authority: e.Authority, Additional: e.Additional,
	}
}

func (e responseDiskEntry) toMemoryEntry() (responseEntry, error) {
	if len(e.Msg) > 0 {
		return responseEntry{
			Msg: e.Msg, UpstreamServer: e.UpstreamServer, UpstreamGroup: e.UpstreamGroup, ASNPassed: e.ASNPassed,
			StoredAt: e.StoredAt, ExpiresAt: e.ExpiresAt, Rcode: dns.RcodeSuccess,
			Question: e.Question, Answer: e.Answer, Authority: e.Authority, Additional: e.Additional,
		}, nil
	}
	msg := &dns.Msg{}
	msg.Response = true
	msg.Authoritative = e.Authoritative
	msg.RecursionAvailable = e.RecursionAvailable
	msg.Rcode = dns.StringToRcode[e.Rcode]
	if msg.Rcode == 0 && e.Rcode == "" {
		msg.Rcode = dns.RcodeSuccess
	}
	for _, q := range e.Question {
		msg.Question = append(msg.Question, dns.Question{
			Name:   dns.Fqdn(q.Name),
			Qtype:  dns.StringToType[q.Type],
			Qclass: dns.StringToClass[q.Class],
		})
	}
	var err error
	if msg.Answer, err = parseRRs(e.Answer); err != nil {
		return responseEntry{}, err
	}
	if msg.Ns, err = parseRRs(e.Authority); err != nil {
		return responseEntry{}, err
	}
	if msg.Extra, err = parseRRs(e.Additional); err != nil {
		return responseEntry{}, err
	}
	packed, err := msg.Pack()
	if err != nil {
		return responseEntry{}, err
	}
	return responseEntry{
		Msg: packed, UpstreamServer: e.UpstreamServer, UpstreamGroup: e.UpstreamGroup, ASNPassed: e.ASNPassed,
		StoredAt: e.StoredAt, ExpiresAt: e.ExpiresAt, Rcode: msg.Rcode,
		Authoritative: msg.Authoritative, RecursionAvailable: msg.RecursionAvailable,
		Question: e.Question, Answer: e.Answer, Authority: e.Authority, Additional: e.Additional,
	}, nil
}

type verdictCache struct {
	mu      sync.RWMutex
	path    string
	items   map[string]verdictEntry
	enabled bool
}

type verdictEntry struct {
	Domain         string    `json:"domain"`
	Result         string    `json:"result"`
	LocalIPs       []string  `json:"local_ips,omitempty"`
	OverseasIPs    []string  `json:"overseas_ips,omitempty"`
	LocalServer    string    `json:"local_server,omitempty"`
	OverseasServer string    `json:"overseas_server,omitempty"`
	UpdatedAt      time.Time `json:"updated_at"`
	ExpiresAt      time.Time `json:"expires_at"`
}

func newVerdictCache(dir string, enabled bool) (*verdictCache, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	c := &verdictCache{path: filepath.Join(dir, "verdict_cache.json"), items: map[string]verdictEntry{}, enabled: enabled}
	_ = c.load()
	return c, nil
}

func (c *verdictCache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.items)
}

func (c *verdictCache) Get(domain string) (verdictEntry, bool) {
	if !c.enabled {
		return verdictEntry{}, false
	}
	key := normalizeDomain(domain)
	c.mu.RLock()
	e, ok := c.items[key]
	c.mu.RUnlock()
	return e, ok && time.Now().Before(e.ExpiresAt)
}

func (c *verdictCache) Put(domain string, e verdictEntry, ttl time.Duration) {
	if !c.enabled {
		return
	}
	key := normalizeDomain(domain)
	now := time.Now()
	e.Domain, e.UpdatedAt, e.ExpiresAt = key, now, now.Add(ttl)
	c.mu.Lock()
	c.items[key] = e
	c.mu.Unlock()
	_ = c.save()
}

func (c *verdictCache) load() error {
	b, err := os.ReadFile(c.path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, &c.items)
}

func (c *verdictCache) save() error {
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

type upstreamClient struct {
	cfg       ScoringConfig
	timeout   time.Duration
	freezeTTL time.Duration
	dnsClient *dns.Client
	http      *http.Client
	resolver  *bootstrapResolver
	ecs       []dns.EDNS0
	log       *appLogger
	mu        sync.Mutex
	stats     map[string]*upstreamStat
}

type upstreamStat struct {
	Address             string
	Score               int
	Latencies           []time.Duration
	Successes           int
	Failures            int
	ConsecutiveFailures int
	FrozenUntil         time.Time
	LastUsed            time.Time
	LastProbe           time.Time
}

type upstreamResult struct {
	Group   string
	Server  string
	Msg     *dns.Msg
	Elapsed time.Duration
	Err     error
}

type sideResult struct {
	side string
	res  upstreamResult
	last upstreamResult
}

func newUpstreamClient(cfg *Config, l *appLogger) (*upstreamClient, error) {
	resolver := newBootstrapResolver(cfg.BootstrapDNS, time.Duration(cfg.Server.UpstreamTimeout)*time.Second)
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		DialContext:     resolver.DialContext,
	}
	u := &upstreamClient{
		cfg:       cfg.Upstream.Scoring,
		timeout:   time.Duration(cfg.Server.UpstreamTimeout) * time.Second,
		freezeTTL: time.Duration(cfg.Server.UpstreamFreezeDuration) * time.Second,
		dnsClient: &dns.Client{Net: "udp", Timeout: time.Duration(cfg.Server.UpstreamTimeout) * time.Second},
		http:      &http.Client{Timeout: time.Duration(cfg.Server.UpstreamTimeout) * time.Second, Transport: transport},
		resolver:  resolver,
		log:       l,
		stats:     map[string]*upstreamStat{},
	}
	if err := u.setECS(cfg.Upstream.EDNSClientSubnet); err != nil {
		return nil, err
	}
	l.Infof(
		"upstream loaded local=%d overseas=%d scoring=%t timeout=%s freeze=%s ecs=%s",
		len(cfg.Upstream.Servers.Local),
		len(cfg.Upstream.Servers.Overseas),
		cfg.Upstream.Scoring.Enabled,
		u.timeout,
		u.freezeTTL,
		u.ecsSummary(),
	)
	return u, nil
}

func (u *upstreamClient) setECS(cfg ECSConfig) error {
	if !cfg.Enabled {
		return nil
	}
	if cfg.IPv4 != "" {
		opt, err := parseECS(cfg.IPv4)
		if err != nil {
			return err
		}
		u.ecs = append(u.ecs, opt)
	}
	if cfg.IPv6 != "" {
		opt, err := parseECS(cfg.IPv6)
		if err != nil {
			return err
		}
		u.ecs = append(u.ecs, opt)
	}
	return nil
}

func (u *upstreamClient) ecsSummary() string {
	if len(u.ecs) == 0 {
		return "disabled"
	}
	var parts []string
	for _, option := range u.ecs {
		if ecs, ok := option.(*dns.EDNS0_SUBNET); ok {
			parts = append(parts, fmt.Sprintf("family=%d address=%s/%d", ecs.Family, ecs.Address, ecs.SourceNetmask))
		}
	}
	return strings.Join(parts, ",")
}

func (u *upstreamClient) QueryFirst(ctx context.Context, group string, servers []string, req *dns.Msg) upstreamResult {
	ordered := u.orderServers(group, servers)
	if len(ordered) == 0 {
		return upstreamResult{Group: group, Err: errors.New("no upstream servers")}
	}
	first := ordered[0]
	res := u.queryOne(ctx, group, first, req)
	if res.Err == nil && res.Msg != nil {
		return res
	}
	if len(ordered) == 1 {
		return res
	}
	child, cancel := context.WithCancel(ctx)
	defer cancel()
	ch := make(chan upstreamResult, len(ordered)-1)
	for _, server := range ordered[1:] {
		go func(s string) { ch <- u.queryOne(child, group, s, req) }(server)
	}
	last := res
	for range ordered[1:] {
		r := <-ch
		if r.Err == nil && r.Msg != nil {
			cancel()
			return r
		}
		last = r
	}
	return last
}

func (u *upstreamClient) QueryValidated(ctx context.Context, group string, servers []string, req *dns.Msg, validate func(*dns.Msg) (*dns.Msg, bool)) (upstreamResult, upstreamResult) {
	ordered := u.orderServers(group, servers)
	if len(ordered) == 0 {
		err := upstreamResult{Group: group, Err: errors.New("no upstream servers")}
		return err, err
	}
	first := u.queryOne(ctx, group, ordered[0], req)
	last := first
	if first.Err == nil && first.Msg != nil {
		if filtered, ok := validate(first.Msg); ok {
			first.Msg = filtered
			return first, last
		}
	}
	if len(ordered) == 1 {
		return upstreamResult{Group: group, Err: errors.New("validation failed"), Server: first.Server, Msg: first.Msg}, last
	}
	child, cancel := context.WithCancel(ctx)
	defer cancel()
	ch := make(chan upstreamResult, len(ordered)-1)
	for _, server := range ordered[1:] {
		go func(s string) { ch <- u.queryOne(child, group, s, req) }(server)
	}
	for range ordered[1:] {
		r := <-ch
		if r.Err == nil && r.Msg != nil {
			last = r
			if filtered, ok := validate(r.Msg); ok {
				r.Msg = filtered
				cancel()
				return r, last
			}
		} else {
			last = r
		}
	}
	return upstreamResult{Group: group, Server: last.Server, Msg: last.Msg, Err: errors.New("validation failed")}, last
}

func (u *upstreamClient) queryOne(ctx context.Context, group, server string, req *dns.Msg) upstreamResult {
	start := time.Now()
	msg, err := u.Query(ctx, server, req.Copy())
	elapsed := time.Since(start)
	if errors.Is(err, context.Canceled) {
		return upstreamResult{Group: group, Server: server, Msg: msg, Elapsed: elapsed, Err: err}
	}
	u.record(group, server, elapsed, err)
	u.logUpstream(group, server, req, start, elapsed, msg, err)
	return upstreamResult{Group: group, Server: server, Msg: msg, Elapsed: elapsed, Err: err}
}

func (u *upstreamClient) Query(ctx context.Context, server string, req *dns.Msg) (*dns.Msg, error) {
	u.applyECS(req)
	if strings.HasPrefix(server, "https://") || strings.HasPrefix(server, "http://") {
		return u.queryDoH(ctx, server, req)
	}
	return u.queryDo53(ctx, server, req)
}

func (u *upstreamClient) queryDo53(ctx context.Context, server string, req *dns.Msg) (*dns.Msg, error) {
	if _, _, err := net.SplitHostPort(server); err != nil {
		server = net.JoinHostPort(server, "53")
	}
	tcp := *u.dnsClient
	udp := *u.dnsClient
	udp.Net = "udp"
	msg, _, err := udp.ExchangeContext(ctx, req, server)
	if err == nil && msg != nil && !msg.Truncated {
		return msg, nil
	}
	tcp.Net = "tcp"
	msg, _, err = tcp.ExchangeContext(ctx, req, server)
	return msg, err
}

func (u *upstreamClient) queryDoH(ctx context.Context, server string, req *dns.Msg) (*dns.Msg, error) {
	packed, err := req.Pack()
	if err != nil {
		return nil, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, server, bytes.NewReader(packed))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("content-type", "application/dns-message")
	httpReq.Header.Set("accept", "application/dns-message")
	resp, err := u.http.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("doh status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, err
	}
	var msg dns.Msg
	if err := msg.Unpack(body); err != nil {
		return nil, err
	}
	return &msg, nil
}

func (u *upstreamClient) orderServers(group string, servers []string) []string {
	now := time.Now()
	u.mu.Lock()
	defer u.mu.Unlock()
	var available []*upstreamStat
	var earliest *upstreamStat
	for _, raw := range servers {
		server := strings.TrimSpace(raw)
		if server == "" {
			continue
		}
		stat := u.statLocked(group, server)
		if now.Before(stat.FrozenUntil) {
			if earliest == nil || stat.FrozenUntil.Before(earliest.FrozenUntil) {
				earliest = stat
			}
			continue
		}
		available = append(available, stat)
	}
	if len(available) == 0 && earliest != nil {
		earliest.FrozenUntil = time.Time{}
		u.log.Infof("upstream thawed group=%s server=%s reason=all_frozen", group, earliest.Address)
		available = append(available, earliest)
	}
	if len(available) == 0 {
		return nil
	}
	if probe := u.pickProbeLocked(available, now); probe != nil {
		return append([]string{probe.Address}, statAddressesExcept(available, probe.Address)...)
	}
	sort.SliceStable(available, func(i, j int) bool {
		if available[i].Score == available[j].Score {
			return available[i].Address < available[j].Address
		}
		return available[i].Score > available[j].Score
	})
	var out []string
	for i := 0; i < len(available); {
		j := i + 1
		for j < len(available) && available[j].Score == available[i].Score {
			j++
		}
		bucket := statAddresses(available[i:j])
		if u.cfg.SameScoreRandom {
			rand.Shuffle(len(bucket), func(a, b int) { bucket[a], bucket[b] = bucket[b], bucket[a] })
		}
		out = append(out, bucket...)
		i = j
	}
	return out
}

func (u *upstreamClient) pickProbeLocked(stats []*upstreamStat, now time.Time) *upstreamStat {
	if u.cfg.lowScoreProbeIntervalParsed <= 0 || len(stats) < 2 {
		return nil
	}
	var lowest *upstreamStat
	for _, s := range stats {
		if lowest == nil || s.Score < lowest.Score {
			lowest = s
		}
	}
	if lowest != nil && now.Sub(lowest.LastProbe) >= u.cfg.lowScoreProbeIntervalParsed {
		lowest.LastProbe = now
		u.log.Infof("upstream low-score probe server=%s score=%d", lowest.Address, lowest.Score)
		return lowest
	}
	return nil
}

func (u *upstreamClient) statLocked(group, server string) *upstreamStat {
	key := group + "|" + server
	stat, ok := u.stats[key]
	if !ok {
		stat = &upstreamStat{Address: server, Score: u.cfg.InitialScore}
		u.stats[key] = stat
	}
	return stat
}

func (u *upstreamClient) record(group, server string, elapsed time.Duration, err error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	stat := u.statLocked(group, server)
	stat.LastUsed = time.Now()
	if err == nil {
		stat.Successes++
		stat.ConsecutiveFailures = 0
		stat.Latencies = append(stat.Latencies, elapsed)
		if len(stat.Latencies) > u.cfg.LatencyWindow {
			stat.Latencies = stat.Latencies[len(stat.Latencies)-u.cfg.LatencyWindow:]
		}
	} else {
		stat.Failures++
		stat.ConsecutiveFailures++
		if isTimeout(err) {
			stat.FrozenUntil = time.Now().Add(u.freezeTTL)
			u.log.Warnf("upstream frozen group=%s server=%s duration=%s reason=%v", group, server, u.freezeTTL, err)
		}
	}
	stat.Score = u.computeScore(stat, err)
}

func (u *upstreamClient) computeScore(stat *upstreamStat, lastErr error) int {
	score := u.cfg.InitialScore
	total := stat.Successes + stat.Failures
	if total > 0 {
		successRate := float64(stat.Successes) / float64(total)
		score += int(math.Round(successRate * float64(u.cfg.SuccessWeight*10)))
	}
	score -= stat.Failures * u.cfg.FailurePenalty
	score -= stat.ConsecutiveFailures * u.cfg.ConsecutiveFailurePenalty
	if isTimeout(lastErr) {
		score -= u.cfg.TimeoutPenalty
	}
	avg := averageLatency(stat.Latencies)
	if avg > 0 {
		score -= int(avg/(100*time.Millisecond)) * u.cfg.LatencyPenaltyPer100ms
	}
	if score < u.cfg.MinScore {
		score = u.cfg.MinScore
	}
	if score > u.cfg.MaxScore {
		score = u.cfg.MaxScore
	}
	return score
}

func (u *upstreamClient) applyECS(req *dns.Msg) {
	if req == nil {
		return
	}
	opt := req.IsEdns0()
	if opt != nil {
		filtered := opt.Option[:0]
		for _, option := range opt.Option {
			if option != nil && option.Option() == dns.EDNS0SUBNET {
				continue
			}
			filtered = append(filtered, option)
		}
		opt.Option = filtered
	}
	if len(u.ecs) == 0 {
		return
	}
	if opt == nil {
		opt = new(dns.OPT)
		opt.Hdr.Name = "."
		opt.Hdr.Rrtype = dns.TypeOPT
		req.Extra = append(req.Extra, opt)
	}
	for _, ecs := range u.ecs {
		opt.Option = append(opt.Option, cloneEDNS0(ecs))
	}
}

func (u *upstreamClient) logUpstream(group, server string, req *dns.Msg, start time.Time, elapsed time.Duration, msg *dns.Msg, err error) {
	status := "OK"
	if msg != nil && msg.Rcode != dns.RcodeSuccess {
		status = dns.RcodeToString[msg.Rcode]
	}
	if err != nil {
		status = err.Error()
	}
	qname := "-"
	if len(req.Question) > 0 {
		qname = req.Question[0].Name
	}
	ips := "-"
	if err == nil && msg != nil {
		ips = formatIPs(extractIPv4(msg))
	}
	u.log.Queryf("%s UPSTREAM %s %s %s %s %s %s %s", formatDurationMS(elapsed), qname, group, server, u.log.formatClock(start), u.log.formatClock(start.Add(elapsed)), status, ips)
}

type bootstrapResolver struct {
	servers []string
	timeout time.Duration
	mu      sync.Mutex
	cache   map[string]bootstrapCacheEntry
}

type bootstrapCacheEntry struct {
	IPs       []net.IP
	ExpiresAt time.Time
}

func newBootstrapResolver(servers []string, timeout time.Duration) *bootstrapResolver {
	return &bootstrapResolver{servers: servers, timeout: timeout, cache: map[string]bootstrapCacheEntry{}}
}

func (r *bootstrapResolver) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil || net.ParseIP(host) != nil {
		var d net.Dialer
		return d.DialContext(ctx, network, address)
	}
	ips, err := r.LookupA(ctx, host)
	if err != nil || len(ips) == 0 {
		var d net.Dialer
		return d.DialContext(ctx, network, address)
	}
	var last error
	for _, ip := range ips {
		var d net.Dialer
		conn, err := d.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if err == nil {
			return conn, nil
		}
		last = err
	}
	return nil, last
}

func (r *bootstrapResolver) LookupA(ctx context.Context, host string) ([]net.IP, error) {
	key := normalizeDomain(host)
	now := time.Now()
	r.mu.Lock()
	if e, ok := r.cache[key]; ok && now.Before(e.ExpiresAt) {
		ips := append([]net.IP{}, e.IPs...)
		r.mu.Unlock()
		return ips, nil
	}
	r.mu.Unlock()
	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(key), dns.TypeA)
	client := &dns.Client{Net: "udp", Timeout: r.timeout}
	var last error
	for _, server := range r.servers {
		if _, _, err := net.SplitHostPort(server); err != nil {
			server = net.JoinHostPort(server, "53")
		}
		msg, _, err := client.ExchangeContext(ctx, req, server)
		if err != nil {
			last = err
			continue
		}
		var ips []net.IP
		var minTTL uint32 = 300
		for _, rr := range msg.Answer {
			if a, ok := rr.(*dns.A); ok {
				ips = append(ips, a.A)
				if a.Hdr.Ttl < minTTL {
					minTTL = a.Hdr.Ttl
				}
			}
		}
		if len(ips) > 0 {
			r.mu.Lock()
			r.cache[key] = bootstrapCacheEntry{IPs: ips, ExpiresAt: time.Now().Add(time.Duration(minTTL) * time.Second)}
			r.mu.Unlock()
			return ips, nil
		}
	}
	if last == nil {
		last = errors.New("bootstrap lookup returned no A records")
	}
	return nil, last
}

type dnsServer struct {
	cfg              *Config
	log              *appLogger
	upstream         *upstreamClient
	respCache        *responseCache
	verdictCache     *verdictCache
	asn              *asnDB
	localFileMissing bool
	localOnly        *Matcher
	overseasOnly     *Matcher
	localDomains     *Matcher
	refreshMu        sync.Mutex
	refreshRunning   map[string]struct{}
}

func newDNSServer(cfg *Config, l *appLogger) (*dnsServer, error) {
	up, err := newUpstreamClient(cfg, l)
	if err != nil {
		return nil, err
	}
	respCache, err := newResponseCache(cfg.Server.CachePath, cfg.Cache.Response.MemorySize, cfg.Cache.Response.Enabled)
	if err != nil {
		return nil, err
	}
	l.Infof("response cache loaded enabled=%t path=%s entries=%d max_size=%d stale_ttl=%ds cleanup_after=%dh", cfg.Cache.Response.Enabled, respCache.path, respCache.Len(), cfg.Cache.Response.MemorySize, cfg.Cache.Response.StaleTTL, cfg.Cache.Response.CleanupAfterHours)
	verdictCache, err := newVerdictCache(cfg.Server.CachePath, cfg.Cache.Comparison.Enabled)
	if err != nil {
		return nil, err
	}
	l.Infof("comparison cache loaded enabled=%t path=%s entries=%d ttl=%dh", cfg.Cache.Comparison.Enabled, verdictCache.path, verdictCache.Len(), cfg.Cache.Comparison.TTLHours)
	localFileMissing := false
	if _, err := os.Stat(cfg.LocalDomains.FilePath); err != nil {
		if os.IsNotExist(err) {
			localFileMissing = true
			l.Warnf("local domains file missing, will update immediately: %s", cfg.LocalDomains.FilePath)
		} else {
			return nil, err
		}
	}
	localPatterns, err := loadDomainFile(cfg.LocalDomains.FilePath)
	if err != nil {
		return nil, err
	}
	l.Infof("local domains loaded path=%s entries=%d local_only=%d overseas_only=%d", cfg.LocalDomains.FilePath, len(localPatterns), len(cfg.Upstream.LocalOnly), len(cfg.Upstream.OverseasOnly))
	var db *asnDB
	if cfg.ASN.Enabled {
		db, err = loadASN(cfg.ASN.FilePath)
		if err != nil {
			return nil, err
		}
		l.Infof("loaded ASN file: %s", cfg.ASN.FilePath)
	} else {
		l.Infof("ASN check disabled")
	}
	return &dnsServer{
		cfg: cfg, log: l, upstream: up, respCache: respCache, verdictCache: verdictCache, asn: db,
		localFileMissing: localFileMissing,
		localOnly:        newMatcher(cfg.Upstream.LocalOnly), overseasOnly: newMatcher(cfg.Upstream.OverseasOnly),
		localDomains: newMatcher(localPatterns), refreshRunning: map[string]struct{}{},
	}, nil
}

func (s *dnsServer) listenAndServe(ctx context.Context) error {
	mux := dns.NewServeMux()
	mux.HandleFunc(".", s.handleDNS)
	udp := &dns.Server{Addr: s.cfg.Server.Listen, Net: "udp", Handler: mux}
	tcp := &dns.Server{Addr: s.cfg.Server.Listen, Net: "tcp", Handler: mux}
	errCh := make(chan error, 2)
	go func() {
		s.log.Infof("listening udp %s", s.cfg.Server.Listen)
		if err := udp.ListenAndServe(); err != nil {
			errCh <- err
		}
	}()
	go func() {
		s.log.Infof("listening tcp %s", s.cfg.Server.Listen)
		if err := tcp.ListenAndServe(); err != nil {
			errCh <- err
		}
	}()
	select {
	case <-ctx.Done():
		_ = udp.Shutdown()
		_ = tcp.Shutdown()
		return nil
	case err := <-errCh:
		_ = udp.Shutdown()
		_ = tcp.Shutdown()
		return err
	}
}

func (s *dnsServer) handleDNS(w dns.ResponseWriter, req *dns.Msg) {
	start := time.Now()
	if len(req.Question) == 0 {
		_ = w.WriteMsg(errorMsg(req, dns.RcodeFormatError))
		return
	}
	q := req.Question[0]
	qname := normalizeDomain(q.Name)
	qtype := dns.TypeToString[q.Qtype]
	route := s.routeFor(q.Name)
	cacheStatus := "skip"
	upstreamServer := "-"
	var msg *dns.Msg
	var err error
	key := responseKey(q)
	if q.Qtype == dns.TypeA {
		if cached, entry, ok, fresh := s.respCache.Get(key); ok {
			cached.Id = req.Id
			if fresh {
				cacheStatus = "hit"
				msg = cached
				upstreamServer = entry.UpstreamServer
				_ = w.WriteMsg(msg)
				s.logQuery(start, q, route, cacheStatus, upstreamServer, msg, nil)
				return
			}
			cacheStatus = "stale"
			setMinTTL(cached, s.cfg.Cache.Response.StaleTTL)
			_ = w.WriteMsg(cached)
			s.logQuery(start, q, route, cacheStatus, entry.UpstreamServer, cached, nil)
			s.refreshInBackground(key, req.Copy())
			return
		}
		cacheStatus = "miss"
		msg, upstreamServer, err = s.resolveA(context.Background(), route, req.Copy(), key)
	} else {
		msg, upstreamServer, err = s.forwardPlain(context.Background(), route, req.Copy())
	}
	if err != nil {
		s.log.Warnf("query failed qname=%s qtype=%s route=%s err=%v", qname, qtype, route, err)
		msg = errorMsg(req, dns.RcodeServerFailure)
	} else if msg != nil {
		msg.Id = req.Id
	}
	writeErr := w.WriteMsg(msg)
	s.logQuery(start, q, route, cacheStatus, upstreamServer, msg, writeErr)
}

func (s *dnsServer) resolveA(parent context.Context, route string, req *dns.Msg, key string) (*dns.Msg, string, error) {
	ctx, cancel := context.WithTimeout(parent, time.Duration(s.cfg.Server.ConcurrentTimeout)*time.Second)
	defer cancel()
	switch route {
	case routeLocal:
		r := s.upstream.QueryFirst(ctx, groupLocal, s.cfg.Upstream.Servers.Local, req)
		if r.Msg != nil && r.Err == nil {
			s.cacheResponse(key, r.Msg, r.Server, groupLocal, false)
		}
		return ensureMsg(r.Msg, req), r.Server, r.Err
	case routeOverseas:
		return s.resolveOverseasOnly(ctx, req, key)
	default:
		return s.resolveDefault(ctx, req, key)
	}
}

func (s *dnsServer) resolveOverseasOnly(ctx context.Context, req *dns.Msg, key string) (*dns.Msg, string, error) {
	known := s.asnKnown(req)
	if !known {
		r := s.upstream.QueryFirst(ctx, groupOverseas, s.cfg.Upstream.Servers.Overseas, req)
		if r.Msg != nil && r.Err == nil {
			s.cacheResponse(key, r.Msg, r.Server, groupOverseas, false)
		}
		return ensureMsg(r.Msg, req), r.Server, r.Err
	}
	valid, last := s.upstream.QueryValidated(ctx, groupOverseas, s.cfg.Upstream.Servers.Overseas, req, s.asnFilter)
	if valid.Err == nil && valid.Msg != nil {
		s.cacheResponse(key, valid.Msg, valid.Server, groupOverseas, true)
		return valid.Msg, valid.Server, nil
	}
	if last.Msg != nil {
		s.log.Warnf("asn rejected all overseas responses qname=%s last_upstream=%s ips=%s", firstQName(req), last.Server, formatIPs(extractIPv4(last.Msg)))
		setMinTTL(last.Msg, s.cfg.Cache.SuspectTTL)
		return last.Msg, last.Server, nil
	}
	return nil, last.Server, last.Err
}

func (s *dnsServer) resolveDefault(ctx context.Context, req *dns.Msg, key string) (*dns.Msg, string, error) {
	qname := firstQName(req)
	known := s.asnKnown(req)
	ch := make(chan sideResult, 2)
	go func() {
		// ASN 校验失败后的「并发重试」只对海外上游；本地侧不因 ASN 失败扫全部本地上游。
		r := s.upstream.QueryFirst(ctx, groupLocal, s.cfg.Upstream.Servers.Local, req)
		ch <- sideResult{side: groupLocal, res: r, last: r}
	}()
	go func() {
		if known {
			r, last := s.upstream.QueryValidated(ctx, groupOverseas, s.cfg.Upstream.Servers.Overseas, req, s.asnFilter)
			ch <- sideResult{side: groupOverseas, res: r, last: last}
			return
		}
		ch <- sideResult{side: groupOverseas, res: s.upstream.QueryFirst(ctx, groupOverseas, s.cfg.Upstream.Servers.Overseas, req)}
	}()

	var local, overseas upstreamResult
	var localLast, overseasLast upstreamResult
	allowFastLocal := false
	if v, ok := s.verdictCache.Get(qname); ok && v.Result == "same" {
		allowFastLocal = true
	}
	for i := 0; i < 2; i++ {
		select {
		case r := <-ch:
			if r.side == groupLocal {
				local, localLast = r.res, r.last
				if allowFastLocal && local.Err == nil && local.Msg != nil && !known {
					go s.completeCompareFromChannel(qname, ch, local, overseas, 1)
					return local.Msg, local.Server, nil
				}
			} else {
				overseas, overseasLast = r.res, r.last
				if overseas.Err == nil && overseas.Msg != nil {
					s.cacheResponse(key, overseas.Msg, overseas.Server, groupOverseas, known)
					go s.completeCompareFromChannel(qname, ch, local, overseas, 1)
					return overseas.Msg, overseas.Server, nil
				}
			}
		case <-ctx.Done():
			i = 2
		}
	}
	if known {
		if local.Err == nil && local.Msg != nil {
			s.log.Warnf("default route using local ASN-accepted fallback qname=%s", qname)
			setMinTTL(local.Msg, s.cfg.Cache.SuspectTTL)
			return local.Msg, local.Server, nil
		}
		if overseasLast.Msg != nil {
			s.log.Warnf("default route returning ASN-rejected overseas response qname=%s upstream=%s ips=%s", qname, overseasLast.Server, formatIPs(extractIPv4(overseasLast.Msg)))
			setMinTTL(overseasLast.Msg, s.cfg.Cache.SuspectTTL)
			return overseasLast.Msg, overseasLast.Server, nil
		}
		if localLast.Msg != nil {
			setMinTTL(localLast.Msg, s.cfg.Cache.SuspectTTL)
			return localLast.Msg, localLast.Server, nil
		}
	}
	if overseas.Msg != nil {
		s.cacheResponse(key, overseas.Msg, overseas.Server, groupOverseas, false)
		return overseas.Msg, overseas.Server, nil
	}
	if local.Msg != nil {
		s.log.Warnf("default route no overseas response, returning local qname=%s upstream=%s", qname, local.Server)
		setMinTTL(local.Msg, s.cfg.Cache.Response.StaleTTL)
		return local.Msg, local.Server, nil
	}
	if overseas.Err != nil {
		return nil, overseas.Server, overseas.Err
	}
	if local.Err != nil {
		return nil, local.Server, local.Err
	}
	return emptyResponse(req), "", nil
}

func (s *dnsServer) completeCompareFromChannel(qname string, ch <-chan sideResult, existingLocal, existingOverseas upstreamResult, remaining int) {
	local, overseas := existingLocal, existingOverseas
	for remaining > 0 {
		r := <-ch
		remaining--
		if r.side == groupLocal {
			local = r.res
		} else {
			overseas = r.res
		}
	}
	s.updateVerdict(qname, local, overseas)
}

func (s *dnsServer) forwardPlain(ctx context.Context, route string, req *dns.Msg) (*dns.Msg, string, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Duration(s.cfg.Server.ConcurrentTimeout)*time.Second)
	defer cancel()
	group, servers := groupOverseas, s.cfg.Upstream.Servers.Overseas
	if route == routeLocal {
		group, servers = groupLocal, s.cfg.Upstream.Servers.Local
	}
	r := s.upstream.QueryFirst(ctx, group, servers, req)
	return ensureMsg(r.Msg, req), r.Server, r.Err
}

func (s *dnsServer) routeFor(name string) string {
	if s.overseasOnly.Match(name) {
		return routeOverseas
	}
	if s.localOnly.Match(name) || s.localDomains.Match(name) {
		return routeLocal
	}
	return routeDefault
}

func (s *dnsServer) refreshInBackground(key string, req *dns.Msg) {
	s.refreshMu.Lock()
	if _, ok := s.refreshRunning[key]; ok {
		s.refreshMu.Unlock()
		return
	}
	s.refreshRunning[key] = struct{}{}
	s.refreshMu.Unlock()
	go func() {
		defer func() {
			s.refreshMu.Lock()
			delete(s.refreshRunning, key)
			s.refreshMu.Unlock()
		}()
		route := s.routeFor(firstQName(req))
		if _, _, err := s.resolveA(context.Background(), route, req, key); err != nil {
			s.log.Warnf("background refresh failed key=%s err=%v", key, err)
		}
	}()
}

func (s *dnsServer) cacheResponse(key string, msg *dns.Msg, upstream, group string, asnPassed bool) {
	s.respCache.Put(key, msg, time.Duration(s.cfg.Server.DomainTTL)*time.Second, upstream, group, asnPassed)
}

func (s *dnsServer) asnKnown(req *dns.Msg) bool {
	if s.asn == nil {
		return false
	}
	names := extractNames(req)
	known, _ := s.asn.check(names, nil)
	return known
}

func (s *dnsServer) asnFilter(msg *dns.Msg) (*dns.Msg, bool) {
	if s.asn == nil || msg == nil {
		return msg, false
	}
	known, good := s.asn.check(extractNames(msg), extractIPv4(msg))
	if known && len(good) > 0 {
		return filterA(msg, good), true
	}
	return msg, false
}

func (s *dnsServer) updateVerdict(qname string, local, overseas upstreamResult) {
	if local.Msg == nil || overseas.Msg == nil {
		return
	}
	localIPs := extractIPv4(local.Msg)
	overseasIPs := extractIPv4(overseas.Msg)
	result := "different"
	if sameIPs(localIPs, overseasIPs) || s.asnBothAccepted(local.Msg, overseas.Msg) || weakSameSubnet(localIPs, overseasIPs, s.cfg.Comparison) {
		result = "same"
	}
	s.verdictCache.Put(qname, verdictEntry{
		Result: result, LocalServer: local.Server, OverseasServer: overseas.Server,
		LocalIPs: ipStrings(localIPs), OverseasIPs: ipStrings(overseasIPs),
	}, time.Duration(s.cfg.Cache.Comparison.TTLHours)*time.Hour)
}

func (s *dnsServer) asnBothAccepted(a, b *dns.Msg) bool {
	if s.asn == nil {
		return false
	}
	knownA, goodA := s.asn.check(extractNames(a), extractIPv4(a))
	knownB, goodB := s.asn.check(extractNames(b), extractIPv4(b))
	return knownA && knownB && len(goodA) > 0 && len(goodB) > 0
}

func (s *dnsServer) startJanitors(ctx context.Context) {
	s.log.Infof("janitors started log_max_age=48h cache_cleanup_after=%dh", s.cfg.Cache.Response.CleanupAfterHours)
	s.log.startJanitor(ctx, s.cfg.Server.LogPath, 48*time.Hour)
	go func() {
		ticker := time.NewTicker(time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				removed := s.respCache.cleanOlderThan(time.Duration(s.cfg.Cache.Response.CleanupAfterHours) * time.Hour)
				if removed > 0 {
					s.log.Infof("cache janitor removed=%d", removed)
				}
			case <-ctx.Done():
				return
			}
		}
	}()
}

func (s *dnsServer) startLocalDomainUpdater(ctx context.Context) {
	if s.cfg.LocalDomains.SourceURL == "" || s.cfg.LocalDomains.FilePath == "" {
		s.log.Infof("local domain updater disabled")
		return
	}
	s.log.Infof("local domain updater started source=%s interval=%dh", s.cfg.LocalDomains.SourceURL, s.cfg.LocalDomains.UpdateIntervalHours)
	go func() {
		if s.localFileMissing {
			s.log.Infof("local domain updater running immediate update because file is missing")
			s.updateLocalDomains(ctx)
		}
		ticker := time.NewTicker(time.Duration(s.cfg.LocalDomains.UpdateIntervalHours) * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				s.updateLocalDomains(ctx)
			case <-ctx.Done():
				return
			}
		}
	}()
}

func (s *dnsServer) updateLocalDomains(ctx context.Context) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.cfg.LocalDomains.SourceURL, nil)
	if err != nil {
		return
	}
	client := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{DialContext: newBootstrapResolver(s.cfg.BootstrapDNS, 5*time.Second).DialContext}}
	resp, err := client.Do(req)
	if err != nil {
		s.log.Warnf("local domain update failed: %v", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		s.log.Warnf("local domain update status=%d", resp.StatusCode)
		return
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32*1024*1024))
	if err != nil {
		s.log.Warnf("local domain update read failed: %v", err)
		return
	}
	var patterns []string
	for _, line := range strings.Split(string(body), "\n") {
		patterns = append(patterns, parseDomainLine(line)...)
	}
	if len(patterns) == 0 {
		s.log.Warnf("local domain update produced empty list")
		return
	}
	if err := os.MkdirAll(filepath.Dir(s.cfg.LocalDomains.FilePath), 0o755); err != nil {
		s.log.Warnf("local domain update mkdir failed: %v", err)
		return
	}
	tmp := s.cfg.LocalDomains.FilePath + ".tmp"
	if err := os.WriteFile(tmp, body, 0o644); err != nil {
		s.log.Warnf("local domain update write failed: %v", err)
		return
	}
	if err := os.Rename(tmp, s.cfg.LocalDomains.FilePath); err != nil {
		s.log.Warnf("local domain update rename failed: %v", err)
		return
	}
	s.localDomains = newMatcher(patterns)
	s.log.Infof("local domains reloaded count=%d", len(patterns))
}

func (s *dnsServer) logQuery(start time.Time, q dns.Question, route, cacheStatus, upstream string, msg *dns.Msg, writeErr error) {
	status := ""
	if msg != nil && msg.Rcode != dns.RcodeSuccess {
		status = dns.RcodeToString[msg.Rcode]
	}
	if writeErr != nil {
		status = writeErr.Error()
	}
	if status == "" {
		status = "-"
	}
	s.log.Queryf("%s %s %s %s %s route=%s cache=%s upstream=%s ips=%s rcode=%s",
		formatDurationMS(time.Since(start)),
		q.Name,
		dns.TypeToString[q.Qtype],
		dns.ClassToString[q.Qclass],
		"QUERY",
		route,
		cacheStatus,
		upstream,
		strings.Join(ipStrings(extractIPv4(msg)), ","),
		status,
	)
}

func parseECS(cidr string) (*dns.EDNS0_SUBNET, error) {
	ip, network, err := net.ParseCIDR(strings.TrimSpace(cidr))
	if err != nil {
		return nil, err
	}
	ones, _ := network.Mask.Size()
	family := uint16(1)
	address := network.IP
	if ip.To4() == nil {
		family = 2
	} else {
		address = network.IP.To4()
	}
	return &dns.EDNS0_SUBNET{Code: dns.EDNS0SUBNET, Family: family, SourceNetmask: uint8(ones), SourceScope: 0, Address: address}, nil
}

func cloneEDNS0(option dns.EDNS0) dns.EDNS0 {
	if ecs, ok := option.(*dns.EDNS0_SUBNET); ok {
		cp := *ecs
		if ecs.Address != nil {
			cp.Address = append(net.IP(nil), ecs.Address...)
		}
		return &cp
	}
	return option
}

func isTimeout(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func averageLatency(in []time.Duration) time.Duration {
	if len(in) == 0 {
		return 0
	}
	var total time.Duration
	for _, d := range in {
		total += d
	}
	return total / time.Duration(len(in))
}

func statAddresses(stats []*upstreamStat) []string {
	out := make([]string, 0, len(stats))
	for _, s := range stats {
		out = append(out, s.Address)
	}
	return out
}

func statAddressesExcept(stats []*upstreamStat, except string) []string {
	var out []string
	for _, s := range stats {
		if s.Address != except {
			out = append(out, s.Address)
		}
	}
	return out
}

func extractIPv4(msg *dns.Msg) []net.IP {
	if msg == nil {
		return nil
	}
	var ips []net.IP
	for _, rr := range msg.Answer {
		if a, ok := rr.(*dns.A); ok && a.A.To4() != nil {
			ips = append(ips, a.A.To4())
		}
	}
	return ips
}

func extractNames(msg *dns.Msg) []string {
	if msg == nil {
		return nil
	}
	seen := map[string]struct{}{}
	var names []string
	add := func(name string) {
		n := normalizeDomain(name)
		if n == "" {
			return
		}
		if _, ok := seen[n]; !ok {
			seen[n] = struct{}{}
			names = append(names, n)
		}
	}
	for _, q := range msg.Question {
		add(q.Name)
	}
	for _, rr := range msg.Answer {
		add(rr.Header().Name)
		if cname, ok := rr.(*dns.CNAME); ok {
			add(cname.Target)
		}
	}
	return names
}

func firstQName(msg *dns.Msg) string {
	if msg == nil || len(msg.Question) == 0 {
		return ""
	}
	return msg.Question[0].Name
}

func sameIPs(a, b []net.IP) bool {
	set := map[string]struct{}{}
	for _, ip := range a {
		if ip4 := ip.To4(); ip4 != nil {
			set[ip4.String()] = struct{}{}
		}
	}
	for _, ip := range b {
		if ip4 := ip.To4(); ip4 != nil {
			if _, ok := set[ip4.String()]; ok {
				return true
			}
		}
	}
	return false
}

func weakSameSubnet(a, b []net.IP, cfg CompareConf) bool {
	for _, x := range a {
		x4 := x.To4()
		if x4 == nil {
			continue
		}
		for _, y := range b {
			y4 := y.To4()
			if y4 == nil {
				continue
			}
			if cfg.AllowSame24AsWeakMatch && x4[0] == y4[0] && x4[1] == y4[1] && x4[2] == y4[2] {
				return true
			}
			if cfg.AllowSame16Match && x4[0] == y4[0] && x4[1] == y4[1] {
				return true
			}
		}
	}
	return false
}

func filterA(msg *dns.Msg, allowed []net.IP) *dns.Msg {
	if msg == nil || len(allowed) == 0 {
		return msg
	}
	set := map[string]struct{}{}
	for _, ip := range allowed {
		if ip4 := ip.To4(); ip4 != nil {
			set[ip4.String()] = struct{}{}
		}
	}
	cp := msg.Copy()
	var answer []dns.RR
	for _, rr := range cp.Answer {
		a, ok := rr.(*dns.A)
		if !ok {
			answer = append(answer, rr)
			continue
		}
		if _, ok := set[a.A.To4().String()]; ok {
			answer = append(answer, rr)
		}
	}
	cp.Answer = answer
	return cp
}

func setMinTTL(msg *dns.Msg, ttl uint32) {
	if msg == nil {
		return
	}
	for _, rr := range append(append([]dns.RR{}, msg.Answer...), append(msg.Ns, msg.Extra...)...) {
		if rr != nil && rr.Header().Rrtype != dns.TypeOPT {
			rr.Header().Ttl = ttl
		}
	}
}

func ensureMsg(msg *dns.Msg, req *dns.Msg) *dns.Msg {
	if msg != nil {
		return msg
	}
	return emptyResponse(req)
}

func emptyResponse(req *dns.Msg) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetReply(req)
	msg.Rcode = dns.RcodeSuccess
	return msg
}

func errorMsg(req *dns.Msg, rcode int) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetRcode(req, rcode)
	return msg
}

func filterCacheableRRs(in []dns.RR) []dns.RR {
	var out []dns.RR
	for _, rr := range in {
		if rr != nil && rr.Header().Rrtype != dns.TypeOPT {
			out = append(out, rr)
		}
	}
	return out
}

func questionStrings(qs []dns.Question) []cacheQuestion {
	out := make([]cacheQuestion, 0, len(qs))
	for _, q := range qs {
		out = append(out, cacheQuestion{
			Name:  q.Name,
			Type:  dns.TypeToString[q.Qtype],
			Class: dns.ClassToString[q.Qclass],
		})
	}
	return out
}

func parseRRs(lines []string) ([]dns.RR, error) {
	out := make([]dns.RR, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, ";") {
			continue
		}
		rr, err := dns.NewRR(line)
		if err != nil {
			return nil, err
		}
		if rr != nil && rr.Header().Rrtype != dns.TypeOPT {
			out = append(out, rr)
		}
	}
	return out, nil
}

func rrStrings(rrs []dns.RR) []string {
	out := make([]string, 0, len(rrs))
	for _, rr := range rrs {
		if rr != nil && rr.Header().Rrtype != dns.TypeOPT {
			out = append(out, rr.String())
		}
	}
	return out
}

func ipStrings(ips []net.IP) []string {
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		if ip4 := ip.To4(); ip4 != nil {
			out = append(out, ip4.String())
		}
	}
	return out
}

func formatIPs(ips []net.IP) string {
	values := ipStrings(ips)
	if len(values) == 0 {
		return "-"
	}
	return strings.Join(values, ",")
}

func formatDurationMS(d time.Duration) string {
	return fmt.Sprintf("%.3fms", float64(d)/float64(time.Millisecond))
}

func init() {
	rand.Seed(time.Now().UnixNano())
}
