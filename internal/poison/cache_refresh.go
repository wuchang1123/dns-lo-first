package poison

import (
	"context"
	"net"
	"strings"
	"time"

	"lo-dns/internal/logger"

	"github.com/miekg/dns"
)

func (c *Checker) runCacheRefresh() {
	if c.upstreamMgr == nil {
		logger.Infof("[CACHE REFRESH] 上游管理器未设置，跳过缓存刷新")
		return
	}

	interval := time.Duration(c.config.CacheRefreshInterval) * time.Minute
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-c.stopChan:
			logger.Infof("[CACHE REFRESH] 停止缓存刷新")
			return
		case <-ticker.C:
			c.refreshCache()
		}
	}
}

func (c *Checker) refreshCache() {
	logger.Infof("[CACHE REFRESH] 开始刷新缓存...")

	domains := c.getAllDomains()
	if len(domains) == 0 {
		logger.Infof("[CACHE REFRESH] 没有域名需要刷新")
		return
	}

	logger.Infof("[CACHE REFRESH] 开始处理 %d 个域名", len(domains))

	for _, domain := range domains {
		c.refreshDomainCache(domain)
		time.Sleep(100 * time.Millisecond)
	}

	logger.Infof("[CACHE REFRESH] 缓存刷新完成")
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
		logger.Infof("[CACHE REFRESH] %s: 清除 %d 个过期通过的IP", domain, len(expiredPassedIPs))
	}

	remainingIPs := c.getRemainingIPs(domain)
	if len(remainingIPs) > 0 {
		logger.Infof("[CACHE REFRESH] %s: 重新验证 %d 个IP", domain, len(remainingIPs))
		for _, ipStr := range remainingIPs {
			ip := net.ParseIP(ipStr)
			if ip != nil {
				originalSource := ""
				c.cacheMu.RLock()
				if domainCache, exists := c.cache[domain]; exists {
					if entry, exists := domainCache[ipStr]; exists {
						originalSource = entry.Source
					}
				}
				c.cacheMu.RUnlock()

				if originalSource == "" {
					originalSource = "overseas"
				}

				result := c.checkTLS(domain, ip, originalSource)
				if result.success {
					logger.Infof("[CACHE REFRESH] %s: IP %s 验证通过", domain, ipStr)
				} else {
					logger.Infof("[CACHE REFRESH] %s: IP %s 验证失败: %s", domain, ipStr, result.err)
				}
				time.Sleep(50 * time.Millisecond)
			}
		}
	}

	if !c.hasPassedCache(domain) {
		logger.Infof("[CACHE REFRESH] %s: 没有通过的缓存，查询上游服务器", domain)
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
		logger.Infof("[CACHE REFRESH] %s: upstreamMgr为nil，跳过上游查询", domain)
		return
	}

	fqdn := domain
	if !strings.HasSuffix(fqdn, ".") {
		fqdn = fqdn + "."
	}

	logger.Infof("[CACHE REFRESH] %s: 开始查询上游服务器...", domain)

	msg := &dns.Msg{
		Question: []dns.Question{
			{Name: fqdn, Qtype: dns.TypeA, Qclass: dns.ClassINET},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	qres := c.upstreamMgr.QueryOverseas(ctx, msg)
	if qres == nil {
		logger.Infof("[CACHE REFRESH] %s: 查询上游服务器返回nil", domain)
		return
	}
	if qres.Err != nil {
		logger.Warnf("[CACHE REFRESH] %s: 查询上游服务器失败: %v", domain, qres.Err)
		return
	}
	if qres.Response == nil {
		logger.Infof("[CACHE REFRESH] %s: 查询上游服务器返回空响应", domain)
		return
	}

	var ips []net.IP
	for _, answer := range qres.Response.Answer {
		if a, ok := answer.(*dns.A); ok {
			ips = append(ips, a.A)
		}
	}

	if len(ips) == 0 {
		logger.Infof("[CACHE REFRESH] %s: 上游服务器没有返回IP", domain)
		return
	}

	logger.Infof("[CACHE REFRESH] %s: 从上游获取 %d 个IP，开始验证", domain, len(ips))
	for _, ip := range ips {
		tlsRes := c.checkTLS(domain, ip, "overseas")
		if tlsRes.success {
			logger.Infof("[CACHE REFRESH] %s: 上游IP %s 验证通过", domain, ip.String())
		} else {
			logger.Infof("[CACHE REFRESH] %s: 上游IP %s 验证失败: %s", domain, ip.String(), tlsRes.err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
