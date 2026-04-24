package poison

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"lo-dns/internal/logger"

	"github.com/miekg/dns"
)

func (c *Checker) checkAndSyncCacheFile() {
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

	if info.Size() == 0 {
		c.cacheMu.Lock()
		c.cache = make(cacheData)
		c.cacheMu.Unlock()
		logger.Infof("[CACHE SYNC] 缓存文件为空，已清空内存缓存")
		return
	}

	data, err := os.ReadFile(c.cacheFile)
	if err != nil {
		logger.Errorf("[CACHE SYNC] 读取缓存文件失败: %v", err)
		return
	}

	var testCache cacheData
	err = json.Unmarshal(data, &testCache)
	if err != nil {
		c.cacheMu.Lock()
		c.cache = make(cacheData)
		c.cacheMu.Unlock()
		logger.Warnf("[CACHE SYNC] 缓存文件JSON格式无效，已清空内存缓存: %v", err)
		return
	}
}

func (c *Checker) getFromCache(domain string, ip net.IP) (bool, string, bool) {
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

func (c *Checker) saveCache() {
	c.cacheMu.RLock()
	validCache := make(cacheData)
	for domain, ipMap := range c.cache {
		validCache[domain] = make(map[string]*cacheEntry)
		for ipStr, entry := range ipMap {
			validCache[domain][ipStr] = entry
		}
	}
	c.cacheMu.RUnlock()

	if len(validCache) == 0 {
		return
	}

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

	c.saveCacheMu.Lock()
	defer c.saveCacheMu.Unlock()

	tmpFile := c.cacheFile + ".tmp"
	err := os.WriteFile(tmpFile, data, 0644)
	if err != nil {
		logger.Errorf("写入临时缓存文件失败: %v", err)
		return
	}

	err = os.Rename(tmpFile, c.cacheFile)
	if err != nil {
		logger.Errorf("重命名缓存文件失败: %v", err)
		os.Remove(tmpFile)
	}
}

func (c *Checker) loadCache() {
	data, err := os.ReadFile(c.cacheFile)
	if err != nil {
		if !os.IsNotExist(err) {
			logger.Errorf("读取缓存文件失败: %v", err)
		}
		return
	}

	var loadedCache cacheData
	err = json.Unmarshal(data, &loadedCache)
	if err != nil {
		logger.Errorf("解析缓存文件失败: %v", err)
		return
	}

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

	count := 0
	for _, ipMap := range c.cache {
		count += len(ipMap)
	}
	logger.Infof("加载了 %d 个缓存项", count)
}
