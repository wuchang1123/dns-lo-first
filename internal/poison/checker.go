package poison

import (
	"context"
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
	"lo-dns/internal/logger"
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
	config      config.PoisonCheckConfig
	httpClient  *http.Client
	sem         chan struct{} // 并发控制
	cache       cacheData
	cacheMu     sync.RWMutex
	saveCacheMu sync.Mutex // 保护文件写入
	cacheTTL    time.Duration
	cacheFile   string
	upstreamMgr *upstream.Manager
	stopChan    chan struct{}

	// ASN相关字段
	domainToOrg   map[string]string      // 域名 -> org
	orgToPrefixes map[string][]net.IPNet // org -> IP段列表
	asnMu         sync.RWMutex
}

// CheckResult 检查结果
type CheckResult struct {
	Passed     bool          // 是否通过检查
	Reason     string        // 未通过原因
	CheckedIPs []net.IP      // 已检查的IP
	Duration   time.Duration // 检查耗时
}

// ASNData ASN数据结构
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

// NewChecker 创建检查器
func NewChecker(cfg config.PoisonCheckConfig, upstreamMgr *upstream.Manager, baseDir string) *Checker {
	cacheDir := filepath.Join(baseDir, "cache")
	os.MkdirAll(cacheDir, 0755)

	checker := &Checker{
		config: cfg,
		httpClient: &http.Client{
			Timeout: time.Duration(cfg.TLSTimeout) * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: false,
					ServerName:         "",
				},
			},
		},
		sem:           make(chan struct{}, cfg.ConcurrentChecks),
		cache:         make(cacheData),
		cacheTTL:      time.Duration(cfg.CacheTTL) * time.Minute,
		cacheFile:     filepath.Join(cacheDir, "tls_cache.json"),
		upstreamMgr:   upstreamMgr,
		stopChan:      make(chan struct{}),
		domainToOrg:   make(map[string]string),
		orgToPrefixes: make(map[string][]net.IPNet),
	}

	checker.loadCache()

	// 加载ASN数据
	if cfg.ASNEnabled {
		asnFilePath := cfg.ASNFilePath
		if !filepath.IsAbs(asnFilePath) {
			asnFilePath = filepath.Join(baseDir, asnFilePath)
		}
		checker.loadASNData(asnFilePath)
	}

	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			checker.checkAndSyncCacheFile()
			checker.saveCache()
		}
	}()

	if cfg.CacheRefreshInterval > 0 {
		go checker.runCacheRefresh()
	}

	return checker
}

// checkAndSyncCacheFile 检查并同步缓存文件状态
func (c *Checker) checkAndSyncCacheFile() {
	// 检查缓存文件是否存在且非空
	info, err := os.Stat(c.cacheFile)
	if err != nil {
		if os.IsNotExist(err) {
			c.cacheMu.Lock()
			c.cache = make(cacheData)
			c.cacheMu.Unlock()
			logger.Infof("[CACHE SYNC] 缓存文件不存在，已清空内存缓存")
		} else {
			logger.Errorf("[CACHE SYNC] 检查缓存文件状态失败: %v", err)
		}
		return
	}

	// 检查文件是否为空
	if info.Size() == 0 {
		// 文件为空，清空内存缓存
		c.cacheMu.Lock()
		c.cache = make(cacheData)
		c.cacheMu.Unlock()
		logger.Infof("[CACHE SYNC] 缓存文件为空，已清空内存缓存")
		return
	}

	// 读取文件内容并验证是否为有效JSON
	data, err := os.ReadFile(c.cacheFile)
	if err != nil {
		logger.Errorf("[CACHE SYNC] 读取缓存文件失败: %v", err)
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
		logger.Warnf("[CACHE SYNC] 缓存文件JSON格式无效，已清空内存缓存: %v", err)
		return
	}
}

// loadASNData 加载ASN数据
func (c *Checker) loadASNData(filePath string) {
	// 读取文件
	data, err := os.ReadFile(filePath)
	if err != nil {
		logger.Errorf("读取ASN文件失败: %v", err)
		return
	}

	// 解析JSON
	var asnData ASNData
	if err := json.Unmarshal(data, &asnData); err != nil {
		logger.Errorf("解析ASN文件失败: %v", err)
		return
	}

	c.asnMu.Lock()
	defer c.asnMu.Unlock()

	// 构建org到IP段的映射
	for org, orgData := range asnData.Orgs {
		prefixes := make([]net.IPNet, 0, len(orgData.Prefixes))
		for _, prefixStr := range orgData.Prefixes {
			_, ipNet, err := net.ParseCIDR(prefixStr)
			if err != nil {
				logger.Errorf("解析IP段 %s 失败: %v", prefixStr, err)
				continue
			}
			prefixes = append(prefixes, *ipNet)
		}
		c.orgToPrefixes[org] = prefixes
	}

	// 构建域名到org的映射
	for _, suffix := range asnData.Suffixes {
		c.domainToOrg[suffix.Suffix] = suffix.Org
	}

	// 统计加载结果
	logger.Infof("加载ASN数据成功: %d个域名映射, %d个组织IP段", len(c.domainToOrg), len(c.orgToPrefixes))
}

// getOrgByDomain 根据域名获取对应的org
func (c *Checker) getOrgByDomain(domain string) string {
	c.asnMu.RLock()
	defer c.asnMu.RUnlock()

	// 直接匹配
	if org, ok := c.domainToOrg[domain]; ok {
		return org
	}

	// 尝试匹配子域名
	parts := strings.Split(domain, ".")
	for i := 1; i < len(parts); i++ {
		subDomain := strings.Join(parts[i:], ".")
		if org, ok := c.domainToOrg[subDomain]; ok {
			return org
		}
	}

	return ""
}

// isIPInOrgPrefixes 判断IP是否在指定org的IP段内
func (c *Checker) isIPInOrgPrefixes(ip net.IP, org string) bool {
	c.asnMu.RLock()
	defer c.asnMu.RUnlock()

	prefixes, ok := c.orgToPrefixes[org]
	if !ok {
		return false
	}

	for _, prefix := range prefixes {
		if prefix.Contains(ip) {
			return true
		}
	}

	return false
}

// CheckIPInOrgPrefixes 检查IP是否在域名对应的组织IP段内
func (c *Checker) CheckIPInOrgPrefixes(domain string, ip net.IP) bool {
	if !c.config.ASNEnabled {
		return false
	}

	org := c.getOrgByDomain(domain)
	if org == "" {
		return false
	}

	return c.isIPInOrgPrefixes(ip, org)
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

// GetCacheFile 获取缓存文件路径
func (c *Checker) GetCacheFile() string {
	return c.cacheFile
}

// GetPassedIPs 获取未过期且passed的IP列表
func (c *Checker) GetPassedIPs(domain string) ([]net.IP, bool) {
	c.checkAndSyncCacheFile()

	c.cacheMu.RLock()
	defer c.cacheMu.RUnlock()

	domainCache, exists := c.cache[domain]
	if !exists {
		return nil, false
	}

	var passedIPs []net.IP
	now := time.Now()

	for ipStr, entry := range domainCache {
		if entry.Passed && !now.After(entry.ExpiresAt) {
			ip := net.ParseIP(ipStr)
			if ip != nil {
				passedIPs = append(passedIPs, ip)
			}
		}
	}

	return passedIPs, len(passedIPs) > 0
}

// BuildDNSResponse 用IP列表构建DNS响应
func (c *Checker) BuildDNSResponse(domain string, ips []net.IP, ttl uint32) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetQuestion(domain+".", dns.TypeA)
	msg.Rcode = dns.RcodeSuccess

	for _, ip := range ips {
		rr := &dns.A{
			Hdr: dns.RR_Header{
				Name:   domain + ".",
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    ttl,
			},
			A: ip,
		}
		msg.Answer = append(msg.Answer, rr)
	}

	return msg
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
			entryStr := fmt.Sprintf(`{"passed":%t,"reason":%q,"source":%q,"expiresAt":%q}`,
				entry.Passed,
				entry.Reason,
				entry.Source,
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
		logger.Errorf("写入临时缓存文件失败: %v", err)
		return
	}

	// 原子性重命名，避免文件损坏
	err = os.Rename(tmpFile, c.cacheFile)
	if err != nil {
		logger.Errorf("重命名缓存文件失败: %v", err)
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
			logger.Errorf("读取缓存文件失败: %v", err)
		}
		return
	}

	// 反序列化缓存
	var loadedCache cacheData
	err = json.Unmarshal(data, &loadedCache)
	if err != nil {
		logger.Errorf("解析缓存文件失败: %v", err)
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
	logger.Infof("加载了 %d 个缓存项", count)
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

	// ASN判断逻辑
	if c.config.ASNEnabled {
		org := c.getOrgByDomain(domain)
		if org != "" {
			if !c.isIPInOrgPrefixes(ip, org) {
				result.err = fmt.Sprintf("IP不在%s的IP段内", org)
				c.setCache(domain, ip, false, result.err, source)
				return result
			}
		}
	}

	// 直接进行TLS握手验证
	conf := &tls.Config{
		ServerName:         domain,
		InsecureSkipVerify: true, // 跳过默认验证，使用自定义验证
		MinVersion:         tls.VersionTLS12,
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			// 解析证书
			certs := make([]*x509.Certificate, len(rawCerts))
			for i, rawCert := range rawCerts {
				cert, err := x509.ParseCertificate(rawCert)
				if err != nil {
					return err
				}
				certs[i] = cert
			}

			// 验证证书链
			opts := x509.VerifyOptions{
				DNSName: domain,
			}
			if _, err := certs[0].Verify(opts); err == nil {
				return nil
			}

			// 如果验证失败，尝试使用自定义域名匹配逻辑
			// 检查所有可能的父域名
			currentDomain := domain
			for {
				if err := verifyCertDomain(certs[0], currentDomain); err == nil {
					return nil
				}
				// 提取父域名
				parts := strings.Split(currentDomain, ".")
				if len(parts) <= 2 {
					break
				}
				currentDomain = strings.Join(parts[1:], ".")
			}

			return fmt.Errorf("certificate not valid for %s", domain)
		},
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

	if len(pattern) > 1 && pattern[0] == '*' {
		if pattern[1] == '.' {
			suffix := pattern[2:]
			// 检查域名是否以 ".suffix" 结尾，或者就是 "suffix"
			if (len(domain) > len(suffix) && domain[len(domain)-len(suffix)-1:] == "."+suffix) || domain == suffix {
				return true
			}
		}
	}

	return false
}

func (c *Checker) runCacheRefresh() {
	if c.upstreamMgr == nil {
		fmt.Println("[CACHE REFRESH] 上游管理器未设置，跳过缓存刷新")
		return
	}

	interval := time.Duration(c.config.CacheRefreshInterval) * time.Minute
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-c.stopChan:
			fmt.Println("[CACHE REFRESH] 停止缓存刷新")
			return
		case <-ticker.C:
			c.refreshCache()
		}
	}
}

func (c *Checker) refreshCache() {
	fmt.Println("[CACHE REFRESH] 开始刷新缓存...")

	domains := c.getAllDomains()
	if len(domains) == 0 {
		fmt.Println("[CACHE REFRESH] 没有域名需要刷新")
		return
	}

	fmt.Printf("[CACHE REFRESH] 开始处理 %d 个域名\n", len(domains))

	for _, domain := range domains {
		c.refreshDomainCache(domain)
		time.Sleep(100 * time.Millisecond)
	}

	fmt.Println("[CACHE REFRESH] 缓存刷新完成")
}

func (c *Checker) getAllDomains() []string {
	c.cacheMu.RLock()
	defer c.cacheMu.RUnlock()

	domains := make([]string, 0, len(c.cache))
	for domain := range c.cache {
		domains = append(domains, domain)
	}
	return domains
}

func (c *Checker) refreshDomainCache(domain string) {
	c.cacheMu.Lock()
	domainCache, exists := c.cache[domain]
	if !exists {
		c.cacheMu.Unlock()
		return
	}

	var expiredPassedIPs []string
	now := time.Now()

	for ipStr, entry := range domainCache {
		if now.After(entry.ExpiresAt) && entry.Passed {
			expiredPassedIPs = append(expiredPassedIPs, ipStr)
			delete(domainCache, ipStr)
		}
	}
	c.cacheMu.Unlock()

	if len(expiredPassedIPs) > 0 {
		fmt.Printf("[CACHE REFRESH] %s: 清除 %d 个过期通过的IP\n", domain, len(expiredPassedIPs))
	}

	remainingIPs := c.getRemainingIPs(domain)
	if len(remainingIPs) > 0 {
		fmt.Printf("[CACHE REFRESH] %s: 重新验证 %d 个IP\n", domain, len(remainingIPs))
		for _, ipStr := range remainingIPs {
			ip := net.ParseIP(ipStr)
			if ip != nil {
				result := c.checkTLS(domain, ip, "cache_refresh")
				if result.success {
					fmt.Printf("[CACHE REFRESH] %s: IP %s 验证通过\n", domain, ipStr)
				} else {
					fmt.Printf("[CACHE REFRESH] %s: IP %s 验证失败: %s\n", domain, ipStr, result.err)
				}
				time.Sleep(50 * time.Millisecond)
			}
		}
	}

	if !c.hasPassedCache(domain) {
		fmt.Printf("[CACHE REFRESH] %s: 没有通过的缓存，查询上游服务器\n", domain)
		c.queryAndVerifyFromUpstream(domain)
	}
}

func (c *Checker) getRemainingIPs(domain string) []string {
	c.cacheMu.RLock()
	defer c.cacheMu.RUnlock()

	var ips []string
	if domainCache, exists := c.cache[domain]; exists {
		for ipStr := range domainCache {
			ips = append(ips, ipStr)
		}
	}
	return ips
}

func (c *Checker) hasPassedCache(domain string) bool {
	c.cacheMu.RLock()
	defer c.cacheMu.RUnlock()

	if domainCache, exists := c.cache[domain]; exists {
		for _, entry := range domainCache {
			if entry.Passed {
				return true
			}
		}
	}
	return false
}

func (c *Checker) queryAndVerifyFromUpstream(domain string) {
	if c.upstreamMgr == nil {
		fmt.Printf("[CACHE REFRESH] %s: upstreamMgr为nil，跳过上游查询\n", domain)
		return
	}

	// 确保域名是完全限定的（以点结尾）用于DNS查询
	fqdn := domain
	if !strings.HasSuffix(fqdn, ".") {
		fqdn = fqdn + "."
	}

	fmt.Printf("[CACHE REFRESH] %s: 开始查询上游服务器...\n", domain)

	msg := &dns.Msg{
		Question: []dns.Question{
			{Name: fqdn, Qtype: dns.TypeA, Qclass: dns.ClassINET},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result := c.upstreamMgr.QueryOverseas(ctx, msg)
	if result == nil {
		fmt.Printf("[CACHE REFRESH] %s: 查询上游服务器返回nil\n", domain)
		return
	}
	if result.Err != nil {
		fmt.Printf("[CACHE REFRESH] %s: 查询上游服务器失败: %v\n", domain, result.Err)
		return
	}
	if result.Response == nil {
		fmt.Printf("[CACHE REFRESH] %s: 查询上游服务器返回空响应\n", domain)
		return
	}

	var ips []net.IP
	for _, answer := range result.Response.Answer {
		if a, ok := answer.(*dns.A); ok {
			ips = append(ips, a.A)
		}
	}

	if len(ips) == 0 {
		fmt.Printf("[CACHE REFRESH] %s: 上游服务器没有返回IP\n", domain)
		return
	}

	fmt.Printf("[CACHE REFRESH] %s: 从上游获取 %d 个IP，开始验证\n", domain, len(ips))
	for _, ip := range ips {
		result := c.checkTLS(domain, ip, "upstream_refresh")
		if result.success {
			fmt.Printf("[CACHE REFRESH] %s: 上游IP %s 验证通过\n", domain, ip.String())
		} else {
			fmt.Printf("[CACHE REFRESH] %s: 上游IP %s 验证失败: %s\n", domain, ip.String(), result.err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func (c *Checker) Stop() {
	close(c.stopChan)
}
