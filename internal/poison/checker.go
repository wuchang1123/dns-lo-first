package poison

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"lo-dns/internal/config"

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
	config      config.PoisonCheckConfig
	httpClient  *http.Client
	sem         chan struct{} // 并发控制
	cache       cacheData
	cacheMu     sync.RWMutex
	saveCacheMu sync.Mutex // 保护文件写入
	cacheTTL    time.Duration
	cacheFile   string
}

// CheckResult 检查结果
type CheckResult struct {
	Passed     bool          // 是否通过检查
	Reason     string        // 未通过原因
	CheckedIPs []net.IP      // 已检查的IP
	Duration   time.Duration // 检查耗时
}

// NewChecker 创建检查器
func NewChecker(cfg config.PoisonCheckConfig) *Checker {
	// 确保缓存目录存在
	cacheDir := "./cache"
	os.MkdirAll(cacheDir, 0755)

	checker := &Checker{
		config: cfg,
		httpClient: &http.Client{
			Timeout: time.Duration(cfg.TLSTimeout) * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: false,
					ServerName:         "", // 将在请求时设置
				},
			},
		},
		sem:       make(chan struct{}, cfg.ConcurrentChecks),
		cache:     make(cacheData),
		cacheTTL:  30 * time.Minute, // 缓存30分钟
		cacheFile: filepath.Join(cacheDir, "tls_cache.json"),
	}

	// 加载缓存
	checker.loadCache()

	// 启动定期保存缓存的 goroutine
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			// 先检查缓存文件状态
			checker.checkAndSyncCacheFile()
			// 然后保存缓存
			checker.saveCache()
		}
	}()

	// 启动后台缓存更新任务
	go checker.startCacheUpdater()

	return checker
}

// checkAndSyncCacheFile 检查并同步缓存文件状态
func (c *Checker) checkAndSyncCacheFile() {
	// 检查缓存文件是否存在且非空
	info, err := os.Stat(c.cacheFile)
	if err != nil {
		if os.IsNotExist(err) {
			// 文件不存在，清空内存缓存
			c.cacheMu.Lock()
			c.cache = make(cacheData)
			c.cacheMu.Unlock()
			fmt.Println("[CACHE SYNC] 缓存文件不存在，已清空内存缓存")
		}
		return
	}

	// 检查文件是否为空
	if info.Size() == 0 {
		// 文件为空，清空内存缓存
		c.cacheMu.Lock()
		c.cache = make(cacheData)
		c.cacheMu.Unlock()
		fmt.Println("[CACHE SYNC] 缓存文件为空，已清空内存缓存")
		return
	}

	// 读取文件内容并验证是否为有效JSON
	data, err := os.ReadFile(c.cacheFile)
	if err != nil {
		return
	}

	// 尝试解析JSON
	var testCache cacheData
	err = json.Unmarshal(data, &testCache)
	if err != nil {
		// JSON无效，清空内存缓存
		c.cacheMu.Lock()
		c.cache = make(cacheData)
		c.cacheMu.Unlock()
		fmt.Printf("[CACHE SYNC] 缓存文件JSON格式无效，已清空内存缓存: %v\n", err)
		return
	}
}

// getFromCache 从缓存获取结果
func (c *Checker) getFromCache(domain string, ip net.IP) (bool, string, bool) {
	// 先检查并同步缓存文件状态
	c.checkAndSyncCacheFile()

	c.cacheMu.RLock()
	domainCache, exists := c.cache[domain]
	c.cacheMu.RUnlock()

	if !exists {
		return false, "", false
	}

	entry, exists := domainCache[ip.String()]
	if !exists || time.Now().After(entry.ExpiresAt) {
		return false, "", false
	}

	return entry.Passed, entry.Reason, true
}

// startCacheUpdater 启动后台缓存更新任务
func (c *Checker) startCacheUpdater() {
	// 使用配置中的更新间隔
	interval := time.Duration(c.config.CacheUpdateInterval) * time.Hour
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// 初始运行一次
	c.updateCache()

	for range ticker.C {
		c.updateCache()
	}
}

// updateCache 更新缓存
func (c *Checker) updateCache() {
	fmt.Println("[CACHE UPDATER] 开始更新缓存...")
	start := time.Now()

	// 1. 提取所有域名
	domains := c.getAllDomains()
	fmt.Printf("[CACHE UPDATER] 提取到 %d 个域名\n", len(domains))

	// 2. 逐个域名处理
	for _, domain := range domains {
		// 2.1 清除过期且passed为true的记录
		c.cleanExpiredRecords(domain)

		// 2.2 查询上游服务器获取IP
		ips := c.queryUpstreamForIPs(domain)
		if len(ips) == 0 {
			continue
		}

		// 2.3 TLS验证上游服务器返回的IP
		c.verifyAndUpdateCache(domain, ips)
	}

	fmt.Printf("[CACHE UPDATER] 缓存更新完成，耗时 %v\n", time.Since(start))
}

// getAllDomains 获取所有域名
func (c *Checker) getAllDomains() []string {
	c.cacheMu.RLock()
	defer c.cacheMu.RUnlock()

	domains := make([]string, 0, len(c.cache))
	for domain := range c.cache {
		domains = append(domains, domain)
	}
	return domains
}

// cleanExpiredRecords 清除过期且passed为true的记录
func (c *Checker) cleanExpiredRecords(domain string) {
	c.cacheMu.Lock()
	defer c.cacheMu.Unlock()

	domainCache, exists := c.cache[domain]
	if !exists {
		return
	}

	now := time.Now()
	for ip, entry := range domainCache {
		if now.After(entry.ExpiresAt) && entry.Passed {
			delete(domainCache, ip)
		}
	}

	// 如果域名缓存为空，删除该域名
	if len(domainCache) == 0 {
		delete(c.cache, domain)
	}
}

// queryUpstreamForIPs 查询上游服务器获取IP
func (c *Checker) queryUpstreamForIPs(domain string) []net.IP {
	// 创建DNS查询消息
	msg := &dns.Msg{}
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeA)

	// 使用默认的本地DNS服务器查询
	client := &dns.Client{
		Net:     "udp",
		Timeout: 5 * time.Second,
	}

	// 使用常见的公共DNS服务器
	servers := []string{
		"8.8.8.8:53",
		"1.1.1.1:53",
		"114.114.114.114:53",
	}

	for _, server := range servers {
		resp, _, err := client.Exchange(msg, server)
		if err == nil && resp != nil && resp.Rcode == dns.RcodeSuccess {
			var ips []net.IP
			for _, answer := range resp.Answer {
				if a, ok := answer.(*dns.A); ok {
					ips = append(ips, a.A)
				}
			}
			if len(ips) > 0 {
				return ips
			}
		}
	}

	return nil
}

// verifyAndUpdateCache 验证IP并更新缓存
func (c *Checker) verifyAndUpdateCache(domain string, ips []net.IP) {
	for _, ip := range ips {
		// 进行TLS验证
		result := c.checkTLS(domain, ip, "local")
		// 验证结果已经通过setCache更新到缓存
		if result.success {
			fmt.Printf("[CACHE UPDATER] 验证通过: %s -> %s\n", domain, ip)
		} else {
			fmt.Printf("[CACHE UPDATER] 验证失败: %s -> %s (%s)\n", domain, ip, result.err)
		}
	}
}

// setCache 设置缓存
func (c *Checker) setCache(domain string, ip net.IP, passed bool, reason string, source string) {
	c.cacheMu.Lock()
	if c.cache[domain] == nil {
		c.cache[domain] = make(map[string]*cacheEntry)
	}
	c.cache[domain][ip.String()] = &cacheEntry{
		Passed:    passed,
		Reason:    reason,
		ExpiresAt: time.Now().Add(c.cacheTTL),
		Source:    source,
	}
	c.cacheMu.Unlock()

	// 立即保存缓存
	go c.saveCache()
}

// saveCache 保存缓存到文件
func (c *Checker) saveCache() {
	c.cacheMu.RLock()
	// 不过滤过期的缓存项，保留所有缓存
	validCache := make(cacheData)
	for domain, ipMap := range c.cache {
		validCache[domain] = make(map[string]*cacheEntry)
		for ipStr, entry := range ipMap {
			validCache[domain][ipStr] = entry
		}
	}
	c.cacheMu.RUnlock()

	// 如果内存缓存为空，不写入文件
	if len(validCache) == 0 {
		return
	}

	// 自定义JSON序列化：每个IP一行
	var builder strings.Builder
	builder.WriteString("{\n")

	domains := make([]string, 0, len(validCache))
	for domain := range validCache {
		domains = append(domains, domain)
	}

	for i, domain := range domains {
		ipMap := validCache[domain]
		builder.WriteString(fmt.Sprintf("  %q: {\n", domain))

		ips := make([]string, 0, len(ipMap))
		for ip := range ipMap {
			ips = append(ips, ip)
		}

		for j, ip := range ips {
			entry := ipMap[ip]
			// 手动构建entry的JSON字符串，确保不换行
			entryStr := fmt.Sprintf(`{"passed":%t,"reason":%q,"expiresAt":%q}`,
				entry.Passed,
				entry.Reason,
				entry.ExpiresAt.Format(time.RFC3339Nano))
			if j < len(ips)-1 {
				builder.WriteString(fmt.Sprintf("    %q: %s,\n", ip, entryStr))
			} else {
				builder.WriteString(fmt.Sprintf("    %q: %s\n", ip, entryStr))
			}
		}

		if i < len(domains)-1 {
			builder.WriteString("  },\n")
		} else {
			builder.WriteString("  }\n")
		}
	}

	builder.WriteString("}\n")
	data := []byte(builder.String())

	// 使用互斥锁保护文件写入
	c.saveCacheMu.Lock()
	defer c.saveCacheMu.Unlock()

	// 先写入临时文件，然后原子性重命名
	tmpFile := c.cacheFile + ".tmp"
	err := os.WriteFile(tmpFile, data, 0644)
	if err != nil {
		fmt.Printf("写入临时缓存文件失败: %v\n", err)
		return
	}

	// 原子性重命名，避免文件损坏
	err = os.Rename(tmpFile, c.cacheFile)
	if err != nil {
		fmt.Printf("重命名缓存文件失败: %v\n", err)
		// 清理临时文件
		os.Remove(tmpFile)
	}
}

// loadCache 从文件加载缓存
func (c *Checker) loadCache() {
	// 读取文件
	data, err := os.ReadFile(c.cacheFile)
	if err != nil {
		if !os.IsNotExist(err) {
			fmt.Printf("读取缓存文件失败: %v\n", err)
		}
		return
	}

	// 反序列化缓存
	var loadedCache cacheData
	err = json.Unmarshal(data, &loadedCache)
	if err != nil {
		fmt.Printf("解析缓存文件失败: %v\n", err)
		return
	}

	// 不过滤过期的缓存项
	c.cacheMu.Lock()
	for domain, ipMap := range loadedCache {
		for ipStr, entry := range ipMap {
			if c.cache[domain] == nil {
				c.cache[domain] = make(map[string]*cacheEntry)
			}
			c.cache[domain][ipStr] = entry
		}
	}
	c.cacheMu.Unlock()

	// 统计缓存项数量
	count := 0
	for _, ipMap := range c.cache {
		count += len(ipMap)
	}
	fmt.Printf("加载了 %d 个缓存项\n", count)
}

// Check 对域名和IP列表进行判毒检查
func (c *Checker) Check(domain string, ips []net.IP, source string) *CheckResult {
	if !c.config.Enabled {
		return &CheckResult{Passed: true, Reason: "check disabled"}
	}

	start := time.Now()
	result := &CheckResult{
		Passed:     true,
		CheckedIPs: ips,
	}

	// 如果没有IP，直接通过
	if len(ips) == 0 {
		result.Reason = "no IPs to check"
		result.Duration = time.Since(start)
		return result
	}

	// 并发TLS检查
	var wg sync.WaitGroup
	resultChan := make(chan *tlsCheckResult, len(ips))

	for _, ip := range ips {
		wg.Add(1)
		go func(ip net.IP) {
			defer wg.Done()
			c.sem <- struct{}{}
			defer func() { <-c.sem }()

			checkResult := c.checkTLS(domain, ip, source)
			resultChan <- checkResult
		}(ip)
	}

	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// 收集结果
	var failedChecks []*tlsCheckResult
	for r := range resultChan {
		if !r.success {
			failedChecks = append(failedChecks, r)
		}
	}

	result.Duration = time.Since(start)

	// 判断结果
	if len(failedChecks) > 0 {
		result.Passed = false
		result.Reason = fmt.Sprintf("TLS check failed for %d IPs", len(failedChecks))
		for _, f := range failedChecks {
			result.Reason += fmt.Sprintf(" [%s: %s]", f.ip, f.err)
		}
	} else {
		result.Reason = "all TLS checks passed"
	}

	return result
}

// tlsCheckResult TLS检查结果
type tlsCheckResult struct {
	ip      net.IP
	success bool
	err     string
}

// checkTLS 对单个IP进行检查（优先IP段检查）
func (c *Checker) checkTLS(domain string, ip net.IP, source string) *tlsCheckResult {
	// 检查缓存
	if passed, _, found := c.getFromCache(domain, ip); found {
		result := &tlsCheckResult{
			ip:      ip,
			success: passed,
		}
		return result
	}

	result := &tlsCheckResult{
		ip:      ip,
		success: false,
	}

	// 直接进行TLS握手验证
	conf := &tls.Config{
		ServerName:         domain,
		InsecureSkipVerify: false,
		MinVersion:         tls.VersionTLS12,
	}

	addr := net.JoinHostPort(ip.String(), fmt.Sprintf("%d", c.config.TLSPort))
	dialer := &net.Dialer{
		Timeout: time.Duration(c.config.TLSTimeout) * time.Second,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", addr, conf)
	if err != nil {
		result.err = fmt.Sprintf("TLS handshake failed: %v", err)
		c.setCache(domain, ip, false, result.err, source)
		return result
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		result.err = "no certificates found"
		c.setCache(domain, ip, false, result.err, source)
		return result
	}

	cert := state.PeerCertificates[0]
	if err := verifyCertDomain(cert, domain); err != nil {
		result.err = fmt.Sprintf("certificate domain mismatch: %v", err)
		c.setCache(domain, ip, false, result.err, source)
		return result
	}

	result.success = true
	c.setCache(domain, ip, true, "TLS handshake successful", source)
	return result
}

// verifyCertDomain 验证证书域名
func verifyCertDomain(cert *x509.Certificate, domain string) error {
	// 检查DNSNames
	for _, name := range cert.DNSNames {
		if matchDomain(name, domain) {
			return nil
		}
	}

	// 检查CommonName
	if matchDomain(cert.Subject.CommonName, domain) {
		return nil
	}

	return fmt.Errorf("domain %s not found in certificate", domain)
}

// matchDomain 域名匹配（支持通配符）
func matchDomain(pattern, domain string) bool {
	if pattern == domain {
		return true
	}

	// 支持通配符 *.example.com 匹配 www.example.com
	if len(pattern) > 1 && pattern[0] == '*' {
		if pattern[1] == '.' {
			suffix := pattern[2:]
			if len(domain) > len(suffix) && domain[len(domain)-len(suffix):] == suffix {
				return true
			}
		}
	}

	return false
}
