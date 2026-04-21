package server

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"lo-dns/internal/cache"
	"lo-dns/internal/config"
	"lo-dns/internal/domain"
	"lo-dns/internal/logger"
	"lo-dns/internal/poison"
	"lo-dns/internal/upstream"

	"github.com/miekg/dns"
)

// Server DNS服务器
type Server struct {
	config         *config.Config
	upstreamMgr    *upstream.Manager
	domainMgr      *domain.Manager
	poisonChecker  *poison.Checker
	pendingQueries map[string]*pendingQuery
	pendingMu      sync.Mutex
	dnsCache       *cache.DNSCache
}

// pendingQuery 待处理查询
type pendingQuery struct {
	waiters []dns.ResponseWriter
	result  *dns.Msg
	err     error
	done    bool
}

// NewServer 创建DNS服务器
func NewServer(cfg *config.Config, upstreamMgr *upstream.Manager, domainMgr *domain.Manager, poisonChecker *poison.Checker) *Server {
	var dnsCache *cache.DNSCache
	if cfg.Server.CacheSize > 0 {
		dnsCache = cache.NewDNSCache(cfg.Server.CacheSize, 5*time.Minute)
		logger.Printf("[CACHE] DNS缓存已启用，大小: %d", cfg.Server.CacheSize)
	} else {
		logger.Println("[CACHE] DNS缓存已禁用")
	}

	return &Server{
		config:         cfg,
		upstreamMgr:    upstreamMgr,
		domainMgr:      domainMgr,
		poisonChecker:  poisonChecker,
		pendingQueries: make(map[string]*pendingQuery),
		dnsCache:       dnsCache,
	}
}

// Start 启动DNS服务器
func (s *Server) Start() error {
	addr := s.config.Server.Listen
	udpServer := &dns.Server{
		Addr:    addr,
		Net:     "udp",
		Handler: s,
	}

	go func() {
		logger.Println("[LO-DNS] 服务器已启动，监听", addr)
		if err := udpServer.ListenAndServe(); err != nil {
			logger.Printf("DNS服务器错误: %v", err)
		}
	}()

	return nil
}

// ServeDNS 处理DNS请求
func (s *Server) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	start := time.Now()

	if len(r.Question) == 0 || r.Question[0].Qtype != dns.TypeA {
		dns.HandleFailed(w, r)
		return
	}

	domain := strings.TrimSuffix(r.Question[0].Name, ".")

	isExpired, cached, _ := s.dnsCache.GetWithExpiry(domain)
	if cached != nil {
		resp := cached.Copy()
		resp.Id = r.Id
		if isExpired {
			for _, answer := range resp.Answer {
				answer.Header().Ttl = 1
			}
			logger.Printf("[CACHE HIT] %s -> 从过期缓存返回 (TTL=1秒)，后台刷新", domain)
			go s.refreshDNSCache(r, domain)
		} else {
			logger.Printf("[CACHE HIT] %s -> 从缓存返回", domain)
		}
		if err := w.WriteMsg(resp); err != nil {
			logger.Printf("[CACHE] %s -> 缓存响应写入失败: %v", domain, err)
		}
		return
	}

	s.pendingMu.Lock()
	if pending, exists := s.pendingQueries[domain]; exists {
		// 已有相同查询正在处理，加入等待队列
		pending.waiters = append(pending.waiters, w)
		s.pendingMu.Unlock()
		logger.Printf("[MERGE] %s 加入等待队列", domain)
		return
	}

	// 创建新的待处理查询
	pending := &pendingQuery{
		waiters: []dns.ResponseWriter{w},
	}
	s.pendingQueries[domain] = pending
	s.pendingMu.Unlock()

	// 执行查询
	var response *dns.Msg
	var err error

	// 检查是否为overpass域名（直接跳过本地DNS查询）
	isOverpassDomain := s.domainMgr.IsOverpassDomain(domain)
	if isOverpassDomain {
		logger.Printf("[OVERPASS DOMAIN] %s -> 直接使用海外DNS", domain)
		response, err = s.queryOverseasOnly(r)
	} else {
		// 检查是否为本地域名
		isLocalDomain := s.domainMgr.IsLocalDomain(domain)

		if isLocalDomain {
			logger.Printf("[LOCAL DOMAIN] %s -> 使用本地DNS", domain)
			response, err = s.queryLocalOnly(r)
		} else {
			response, err = s.queryWithPoisonCheck(r, domain)
		}
	}

	// 处理结果
	s.pendingMu.Lock()
	pending.result = response
	pending.err = err
	pending.done = true

	// 通知所有等待者并清理
	waiters := pending.waiters
	delete(s.pendingQueries, domain)
	s.pendingMu.Unlock()

	// 向所有等待者发送响应
	for _, waiter := range waiters {
		if pending.err != nil || pending.result == nil {
			dns.HandleFailed(waiter, r)
		} else {
			resp := pending.result.Copy()
			resp.Id = r.Id
			waiter.WriteMsg(resp)
		}
	}

	if pending.err == nil && pending.result != nil {
		s.dnsCache.Set(domain, pending.result)
	}

	logger.Printf("[QUERY OK] %s -> 响应 %d 个等待者，耗时 %v", domain, len(waiters), time.Since(start))
}

// queryLocalOnly 只查询本地DNS
func (s *Server) queryLocalOnly(r *dns.Msg) (*dns.Msg, error) {
	result := s.upstreamMgr.QueryLocal(context.Background(), r)
	if result.Err != nil {
		return nil, result.Err
	}
	return result.Response, nil
}

// queryOverseasOnly 只使用海外DNS查询（并进行TLS校验）
func (s *Server) queryOverseasOnly(r *dns.Msg) (*dns.Msg, error) {
	// 提取域名
	domain := strings.TrimSuffix(r.Question[0].Name, ".")

	// 乐观缓存策略：先检查TLS验证缓存是否有通过的IP
	passedIPs, hasValidCache := s.getPassedIPsFromCache(domain)
	if hasValidCache {
		// 构建响应消息
		resp := buildResponse(r, passedIPs, 60)

		// 后台运行完整的查询和验证流程，更新缓存
		go func() {
			result := s.upstreamMgr.QueryOverseas(context.Background(), r)
			if result.Err != nil {
				logger.Printf("[OVERPASS BACKGROUND] %s -> 查询失败: %v", domain, result.Err)
				return
			}

			// 提取IP并进行TLS验证
			ips := extractIPs(result.Response)
			s.processTLSCheck(domain, ips, "overseas", "[OVERPASS BACKGROUND]")
		}()

		logger.Printf("[OVERPASS CACHE] %s -> 从缓存返回 %d 个通过的IP", domain, len(resp.Answer))
		return resp, nil
	}

	// 缓存未命中，执行正常查询流程
	result := s.upstreamMgr.QueryOverseas(context.Background(), r)
	if result.Err != nil {
		return nil, result.Err
	}

	// 提取IP并进行TLS验证
	ips := extractIPs(result.Response)
	s.processTLSCheck(domain, ips, "overseas", "[OVERPASS CHECK]")

	return result.Response, nil
}

// getPassedIPsFromCache 从缓存获取通过的IP（乐观缓存策略）
func (s *Server) getPassedIPsFromCache(domain string) ([]net.IP, bool) {
	// 从 poisonChecker 获取缓存文件路径
	cacheFile := s.poisonChecker.GetCacheFile()

	// 检查缓存文件是否存在且非空
	info, err := os.Stat(cacheFile)
	if err != nil {
		if os.IsNotExist(err) {
			logger.Printf("[CACHE CHECK] %s -> 缓存文件不存在", domain)
		}
		return nil, false
	}

	if info.Size() == 0 {
		logger.Printf("[CACHE CHECK] %s -> 缓存文件为空", domain)
		return nil, false
	}

	data, err := os.ReadFile(cacheFile)
	if err != nil {
		logger.Errorf("[CACHE CHECK] %s -> 读取缓存文件失败: %v", domain, err)
		return nil, false
	}

	type cacheEntry struct {
		Passed    bool      `json:"passed"`
		Reason    string    `json:"reason"`
		ExpiresAt time.Time `json:"expiresAt"`
	}

	type cacheData map[string]map[string]*cacheEntry

	var cache cacheData
	err = json.Unmarshal(data, &cache)
	if err != nil {
		logger.Printf("[CACHE CHECK] %s -> 缓存文件JSON格式无效: %v", domain, err)
		return nil, false
	}

	domainCache, exists := cache[domain]
	if !exists {
		return nil, false
	}

	var passedIPs []net.IP
	var expiredIPs []string
	now := time.Now()

	for ipStr, entry := range domainCache {
		if entry.Passed {
			ip := net.ParseIP(ipStr)
			if ip != nil {
				passedIPs = append(passedIPs, ip)
				if len(passedIPs) >= 6 {
					break
				}
			}
		}
		// 检查是否过期
		if now.After(entry.ExpiresAt) {
			expiredIPs = append(expiredIPs, ipStr)
		}
	}

	// 如果有过期的缓存项，在后台默默更新
	if len(expiredIPs) > 0 {
		go func() {
			// 触发一次DNS查询来更新缓存
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			dnsMsg := new(dns.Msg)
			dnsMsg.SetQuestion(domain+".", dns.TypeA)

			// 并发查询本地和海外DNS来更新缓存
			localChan := make(chan *upstream.Result, 1)
			overseasChan := make(chan *upstream.Result, 1)

			go func() {
				localChan <- s.upstreamMgr.QueryLocal(ctx, dnsMsg)
			}()

			go func() {
				overseasChan <- s.upstreamMgr.QueryOverseas(ctx, dnsMsg)
			}()

			// 等待结果完成（不阻塞主流程）
			select {
			case <-localChan:
			case <-time.After(3 * time.Second):
			}

			select {
			case <-overseasChan:
			case <-time.After(5 * time.Second):
			}

			logger.Printf("[CACHE REFRESH] %s -> 后台更新 %d 个过期缓存项", domain, len(expiredIPs))
		}()
	}

	return passedIPs, len(passedIPs) > 0
}

// queryWithPoisonCheck 使用判毒系统查询
func (s *Server) queryWithPoisonCheck(r *dns.Msg, domain string) (*dns.Msg, error) {
	// 先检查缓存是否有通过的IP（乐观缓存策略）
	passedIPs, hasValidCache := s.getPassedIPsFromCache(domain)
	if hasValidCache {
		// 构建响应消息
		resp := buildResponse(r, passedIPs, 300)

		// 记录日志
		logger.Printf("[CACHE PASS] %s -> 从缓存返回 %d 个通过的IP", domain, len(passedIPs))

		// 在后台继续执行后续程序（查询本地和海外DNS）
		go func() {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			// 并发查询本地和海外DNS
			localChan := make(chan *upstream.Result, 1)
			overseasChan := make(chan *upstream.Result, 1)

			go func() {
				localChan <- s.upstreamMgr.QueryLocal(ctx, r)
			}()

			go func() {
				overseasChan <- s.upstreamMgr.QueryOverseas(ctx, r)
			}()

			var localResult, overseasResult *upstream.Result

			// 等待本地结果
			select {
			case localResult = <-localChan:
				if localResult.Err == nil && localResult.Response != nil {
					// 获取本地返回的IP列表
					allIps := extractIPs(localResult.Response)
					s.processTLSCheck(domain, allIps, "local", "[POISON CHECK]")
				}
			case <-time.After(3 * time.Second):
				logger.Printf("[TIMEOUT] %s -> 本地DNS超时", domain)
			}

			// 等待海外结果（如果需要）
			select {
			case overseasResult = <-overseasChan:
				if overseasResult.Err == nil && overseasResult.Response != nil {
					// 提取IP并进行TLS验证
					ips := extractIPs(overseasResult.Response)
					s.processTLSCheck(domain, ips, "overseas", "[OVERSEAS CHECK]")
				}
			case <-time.After(5 * time.Second):
				logger.Printf("[TIMEOUT] %s -> 海外DNS超时", domain)
			}
		}()

		return resp, nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 并发查询本地和海外DNS
	localChan := make(chan *upstream.Result, 1)
	overseasChan := make(chan *upstream.Result, 1)

	go func() {
		localChan <- s.upstreamMgr.QueryLocal(ctx, r)
	}()

	go func() {
		overseasChan <- s.upstreamMgr.QueryOverseas(ctx, r)
	}()

	var localResult, overseasResult *upstream.Result

	// 等待本地结果
	select {
	case localResult = <-localChan:
		if localResult.Err == nil && localResult.Response != nil {
			// 获取本地返回的IP列表
			allIps := extractIPs(localResult.Response)
			// 随机选择最多1个IP进行检查
			ips := randomSelectIPs(allIps)

			// 进行判毒检查（使用原始域名，因为CDN证书通常对原始域名有效）
			checkResult := s.poisonChecker.Check(domain, ips, "local")

			// 格式化IP列表用于日志
			var ipsStr string
			if len(checkResult.CheckedIPs) > 0 {
				var ipList []string
				for _, ip := range checkResult.CheckedIPs {
					ipList = append(ipList, ip.String())
				}
				ipsStr = " [" + strings.Join(ipList, ", ") + "]"
			}

			logger.Printf("[POISON CHECK] %s: 检查 %d/%d 个IP%s, passed=%v, reason=%s, duration=%v",
				domain, len(ips), len(allIps), ipsStr, checkResult.Passed, checkResult.Reason, checkResult.Duration)

			if checkResult.Passed {
				// 判毒通过，直接返回本地结果，不等待海外
				logger.Printf("[LOCAL OK] %s -> 判毒通过，使用本地DNS", domain)

				// 在后台对剩余IP进行TLS验证并缓存结果
				if len(allIps) > 1 {
					go func() {
						remainingIPs := make([]net.IP, 0, len(allIps)-1)
						for _, ip := range allIps {
							found := false
							for _, selectedIP := range ips {
								if ip.Equal(selectedIP) {
									found = true
									break
								}
							}
							if !found {
								remainingIPs = append(remainingIPs, ip)
							}
						}
						if len(remainingIPs) > 0 {
							s.poisonChecker.Check(domain, remainingIPs, "local")
							logger.Printf("[BACKGROUND CHECK] %s: 后台验证 %d 个剩余IP", domain, len(remainingIPs))
						}
					}()
				}

				cancel() // 取消海外查询
				return localResult.Response, nil
			}
		}
	case <-time.After(3 * time.Second):
		logger.Printf("[TIMEOUT] %s -> 本地DNS超时", domain)
	}

	// 判毒不通过或本地失败，等待海外结果
	logger.Printf("[WAIT OVERSEAS] %s -> 等待海外DNS", domain)

	select {
	case overseasResult = <-overseasChan:
		if overseasResult.Err == nil && overseasResult.Response != nil {
			// 提取IP并进行TLS验证
			ips := extractIPs(overseasResult.Response)
			if len(ips) > 0 {
				// 随机选择一个IP
				selectedIPs := randomSelectIPs(ips)
				if len(selectedIPs) > 0 {
					// 进行TLS验证（使用原始域名，因为CDN证书通常对原始域名有效）
					checkResult := s.poisonChecker.Check(domain, selectedIPs, "overseas")

					// 格式化IP列表用于日志
					var ipsStr string
					if len(checkResult.CheckedIPs) > 0 {
						var ipList []string
						for _, ip := range checkResult.CheckedIPs {
							ipList = append(ipList, ip.String())
						}
						ipsStr = " [" + strings.Join(ipList, ", ") + "]"
					}

					logger.Printf("[OVERSEAS CHECK] %s: 检查 1/%d 个IP%s, passed=%v, reason=%s, duration=%v",
						domain, len(ips), ipsStr, checkResult.Passed, checkResult.Reason, checkResult.Duration)

					if !checkResult.Passed {
						// 验证失败，直接返回，TTL为1
						logger.Printf("[OVERSEAS FAIL] %s -> TLS验证失败，直接返回，但是ttl设置为1", domain)
						emptyResp := new(dns.Msg)
						emptyResp.SetReply(r)
						emptyResp.Rcode = dns.RcodeSuccess
						// 确保TTL为1
						for _, answer := range emptyResp.Answer {
							answer.Header().Ttl = 1
						}
						return emptyResp, nil
					}
				}

				// 在后台对剩余IP进行TLS验证并缓存结果
				if len(ips) > 1 {
					go func() {
						remainingIPs := make([]net.IP, 0, len(ips)-1)
						for _, ip := range ips {
							found := false
							for _, selectedIP := range selectedIPs {
								if ip.Equal(selectedIP) {
									found = true
									break
								}
							}
							if !found {
								remainingIPs = append(remainingIPs, ip)
							}
						}
						if len(remainingIPs) > 0 {
							s.poisonChecker.Check(domain, remainingIPs, "overseas")
							logger.Printf("[BACKGROUND CHECK] %s: 后台验证 %d 个剩余IP", domain, len(remainingIPs))
						}
					}()
				}
			}

			logger.Printf("[OVERSEAS OK] %s -> 使用海外DNS", domain)
			return overseasResult.Response, nil
		}
	case <-time.After(5 * time.Second):
		logger.Printf("[TIMEOUT] %s -> 海外DNS超时", domain)
	}

	return nil, fmt.Errorf("查询失败")
}

// extractIPs 从DNS响应中提取IP列表
func extractIPs(msg *dns.Msg) []net.IP {
	var ips []net.IP
	for _, rr := range msg.Answer {
		if a, ok := rr.(*dns.A); ok {
			ips = append(ips, a.A)
		}
	}
	return ips
}

// refreshDNSCache 后台刷新DNS缓存
func (s *Server) refreshDNSCache(r *dns.Msg, domain string) {
	// 检查是否为overpass域名
	isOverpassDomain := s.domainMgr.IsOverpassDomain(domain)
	if isOverpassDomain {
		result := s.upstreamMgr.QueryOverseas(context.Background(), r)
		if result.Err == nil && result.Response != nil {
			s.dnsCache.Set(domain, result.Response)
			logger.Printf("[CACHE REFRESH] %s -> 海外DNS缓存已更新", domain)
		}
		return
	}

	// 检查是否为本地域名
	isLocalDomain := s.domainMgr.IsLocalDomain(domain)
	if isLocalDomain {
		result := s.upstreamMgr.QueryLocal(context.Background(), r)
		if result.Err == nil && result.Response != nil {
			s.dnsCache.Set(domain, result.Response)
			logger.Printf("[CACHE REFRESH] %s -> 本地DNS缓存已更新", domain)
		}
		return
	}

	// 其他域名：同时查询本地和海外
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	localResult, overseasResult := s.upstreamMgr.QueryAll(ctx, r)

	if localResult != nil && localResult.Err == nil && localResult.Response != nil {
		ips := extractIPs(localResult.Response)
		s.processTLSCheck(domain, ips, "local", "[CACHE REFRESH]")
	}

	if overseasResult != nil && overseasResult.Err == nil && overseasResult.Response != nil {
		ips := extractIPs(overseasResult.Response)
		s.processTLSCheck(domain, ips, "overseas", "[CACHE REFRESH]")

		// 使用海外DNS结果更新缓存
		s.dnsCache.Set(domain, overseasResult.Response)
		logger.Printf("[CACHE REFRESH] %s -> 海外DNS缓存已更新", domain)
	}
}

// getTargetDomain 从DNS响应中获取目标域名（处理CNAME）
func getTargetDomain(msg *dns.Msg, originalDomain string) string {
	for _, rr := range msg.Answer {
		if cname, ok := rr.(*dns.CNAME); ok {
			// 找到CNAME记录，返回目标域名（去除末尾的点）
			return strings.TrimSuffix(cname.Target, ".")
		}
	}
	// 没有CNAME记录，返回原始域名
	return originalDomain
}

// randomSelectIPs 随机选择最多1个IP
func randomSelectIPs(ips []net.IP) []net.IP {
	if len(ips) <= 1 {
		return ips
	}
	// 使用Fisher-Yates算法随机打乱切片
	for i := len(ips) - 1; i > 0; i-- {
		j := rand.IntN(i + 1)
		ips[i], ips[j] = ips[j], ips[i]
	}
	return ips[:1]
}

// buildResponse 构建DNS响应消息
func buildResponse(r *dns.Msg, ips []net.IP, ttl uint32) *dns.Msg {
	resp := new(dns.Msg)
	resp.SetReply(r)
	resp.Rcode = dns.RcodeSuccess

	// 添加最多6个IP
	for i, ip := range ips {
		if i >= 6 {
			break
		}
		resp.Answer = append(resp.Answer, &dns.A{
			Hdr: dns.RR_Header{
				Name:   r.Question[0].Name,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    ttl,
			},
			A: ip,
		})
	}

	return resp
}

// processTLSCheck 处理TLS验证和后台检查
func (s *Server) processTLSCheck(domain string, ips []net.IP, source string, logPrefix string) {
	if len(ips) == 0 {
		return
	}

	// 随机选择一个IP进行检查
	selectedIPs := randomSelectIPs(ips)
	if len(selectedIPs) > 0 {
		// 进行TLS验证
		checkResult := s.poisonChecker.Check(domain, selectedIPs, source)

		// 格式化IP列表用于日志
		var ipsStr string
		if len(checkResult.CheckedIPs) > 0 {
			var ipList []string
			for _, ip := range checkResult.CheckedIPs {
				ipList = append(ipList, ip.String())
			}
			ipsStr = " [" + strings.Join(ipList, ", ") + "]"
		}

		logger.Printf("%s %s: 检查 1/%d 个IP%s, passed=%v, reason=%s, duration=%v",
			logPrefix, domain, len(ips), ipsStr, checkResult.Passed, checkResult.Reason, checkResult.Duration)

		// 在后台对剩余IP进行TLS验证并缓存结果
		if len(ips) > 1 {
			go func() {
				remainingIPs := make([]net.IP, 0, len(ips)-1)
				for _, ip := range ips {
					found := false
					for _, selectedIP := range selectedIPs {
						if ip.Equal(selectedIP) {
							found = true
							break
						}
					}
					if !found {
						remainingIPs = append(remainingIPs, ip)
					}
				}
				if len(remainingIPs) > 0 {
					s.poisonChecker.Check(domain, remainingIPs, source)
					logger.Printf("[BACKGROUND CHECK] %s: 后台验证 %d 个剩余IP", domain, len(remainingIPs))
				}
			}()
		}
	}
}
