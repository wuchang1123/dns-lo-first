package poison

import (
	"net"
	"sync"
	"time"

	"lo-dns/internal/config"
	"lo-dns/internal/upstream"

	"github.com/miekg/dns"
)

// cacheEntry 缓存项
type cacheEntry struct {
	Passed    bool      `json:"passed"`
	Reason    string    `json:"reason"`
	ExpiresAt time.Time `json:"expiresAt"`
	Source    string    `json:"source"` // local 或 overseas
}

// cacheData 缓存数据结构：域名 -> IP -> 缓存项
type cacheData map[string]map[string]*cacheEntry

// Checker 判毒检查器
type Checker struct {
	config config.PoisonCheckConfig
	sem    chan struct{} // 并发控制

	cache       cacheData
	cacheMu     sync.RWMutex
	saveCacheMu sync.Mutex // 保护文件写入
	cacheTTL    time.Duration
	cacheFile   string

	upstreamMgr *upstream.Manager
	stopChan    chan struct{}

	// ASN
	domainToOrg   map[string]string
	orgToPrefixes map[string][]net.IPNet
	dnsClient     *dns.Client
	asnMu         sync.RWMutex
	asnManualPath string
	asnMergedPath string

	// skip_tls_verify：命中则跳过 TLS 与 ASN 前缀校验
	tlsSkipVerifySet          map[string]struct{}
	tlsSkipVerifyWildcardOnly map[string]struct{}
}

// CheckResult 检查结果
type CheckResult struct {
	Passed     bool
	Reason     string
	CheckedIPs []net.IP
	Duration   time.Duration
}

// ASNData ASN 文件 JSON 结构
type ASNData struct {
	Version int `json:"version"`
	Orgs    map[string]struct {
		Prefixes []string `json:"prefixes"`
	} `json:"orgs"`
	Suffixes []struct {
		Suffix string `json:"suffix"`
		Org    string `json:"org"`
	} `json:"suffixes"`
}

// tlsCheckResult 单 IP TLS 检查结果
type tlsCheckResult struct {
	ip      net.IP
	success bool
	err     string
}
