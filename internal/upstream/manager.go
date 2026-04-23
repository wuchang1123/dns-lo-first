package upstream

import (
	"context"
	"fmt"
	"sync"
	"time"

	"lo-dns/internal/logger"

	"github.com/miekg/dns"
)

// ServerType 上游服务器类型
type ServerType int

const (
	LocalServer ServerType = iota
	OverseasServer
)

// Result 查询结果
type Result struct {
	Response  *dns.Msg
	Server    string
	Type      ServerType
	Err       error
	Duration  time.Duration
	Timestamp time.Time
}

// Manager 上游服务器管理器
type Manager struct {
	localServers    []string
	overseasServers []string
	client          *dns.Client
	timeout         time.Duration

	// 本地DNS缓存
	localCache    map[string]*Result
	localCacheMu  sync.RWMutex
	localCacheTTL time.Duration
}

// NewManager 创建上游管理器
func NewManager(local, overseas []string) *Manager {
	return &Manager{
		localServers:    local,
		overseasServers: overseas,
		client: &dns.Client{
			Net:     "udp",
			Timeout: 5 * time.Second,
		},
		timeout:       5 * time.Second,
		localCache:    make(map[string]*Result),
		localCacheTTL: 60 * time.Second, // 默认缓存60秒
	}
}

// QueryLocal 查询本地DNS（乐观缓存：过期也返回，后台更新）
func (m *Manager) QueryLocal(ctx context.Context, msg *dns.Msg) *Result {
	// 生成缓存键
	cacheKey := m.generateCacheKey(msg)

	// 检查缓存
	if result := m.getFromCache(cacheKey); result != nil {
		// 检查缓存是否过期
		if time.Since(result.Timestamp) > m.localCacheTTL {
			// 缓存过期，先返回缓存结果，TTL设置为3，后台更新
			logger.Printf("[CACHE HIT] %s -> 从本地DNS缓存返回（过期，TTL=3，后台更新）", cacheKey)
			// 复制响应并修改TTL
			if result.Response != nil {
				respCopy := result.Response.Copy()
				// 修改所有Answer的TTL为3
				for _, answer := range respCopy.Answer {
					answer.Header().Ttl = 3
				}
				// 创建新的结果对象
				result = &Result{
					Response:  respCopy,
					Server:    result.Server,
					Type:      result.Type,
					Err:       result.Err,
					Duration:  result.Duration,
					Timestamp: result.Timestamp,
				}
			}
			// 后台执行新的查询并更新缓存
			go func() {
				// 创建新的上下文，避免原上下文被取消
				bgCtx, cancel := context.WithTimeout(context.Background(), m.timeout)
				defer cancel()
				// 执行查询
				newResult := m.queryServers(bgCtx, msg, m.localServers, LocalServer)
				// 更新缓存
				if newResult.Err == nil && newResult.Response != nil {
					m.saveToCache(cacheKey, newResult)
					logger.Printf("[CACHE UPDATE] %s -> 本地DNS缓存已更新", cacheKey)
				}
			}()
		} else {
			// 缓存未过期，直接返回
			logger.Printf("[CACHE HIT] %s -> 从本地DNS缓存返回", cacheKey)
		}
		return result
	}

	// 缓存未命中，执行查询
	result := m.queryServers(ctx, msg, m.localServers, LocalServer)

	// 存入缓存
	if result.Err == nil && result.Response != nil {
		m.saveToCache(cacheKey, result)
	}

	return result
}

// QueryOverseas 查询海外DNS
func (m *Manager) QueryOverseas(ctx context.Context, msg *dns.Msg) *Result {
	return m.queryServers(ctx, msg, m.overseasServers, OverseasServer)
}

// QueryAll 并发查询所有上游
func (m *Manager) QueryAll(ctx context.Context, msg *dns.Msg) (*Result, *Result) {
	var wg sync.WaitGroup
	var localResult, overseasResult *Result

	wg.Add(2)

	go func() {
		defer wg.Done()
		localResult = m.QueryLocal(ctx, msg)
	}()

	go func() {
		defer wg.Done()
		overseasResult = m.QueryOverseas(ctx, msg)
	}()

	wg.Wait()
	return localResult, overseasResult
}

// queryServers 查询服务器列表
func (m *Manager) queryServers(ctx context.Context, msg *dns.Msg, servers []string, serverType ServerType) *Result {
	if len(servers) == 0 {
		return &Result{Err: fmt.Errorf("no servers available"), Type: serverType}
	}

	// 提取域名用于日志
	var domain string
	if len(msg.Question) > 0 {
		domain = msg.Question[0].Name
	}

	// 并发查询所有服务器，返回第一个成功的结果
	resultChan := make(chan *Result, len(servers))
	var wg sync.WaitGroup

	for _, server := range servers {
		wg.Add(1)
		go func(srv string) {
			defer wg.Done()
			result := m.querySingle(ctx, msg, srv, serverType)
			if result.Err == nil && result.Response != nil && result.Response.Rcode == dns.RcodeSuccess {
				select {
				case resultChan <- result:
				default:
				}
			} else {
				// 记录失败的服务器和错误
				logger.Errorf("[UPSTREAM] %s 服务器 %s 查询 %s 失败: %v", serverTypeToString(serverType), srv, domain, result.Err)
			}
		}(server)
	}

	// 等待所有查询完成或超时
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// 获取第一个成功结果
	for result := range resultChan {
		return result
	}

	// 所有查询都失败，返回最后一个错误
	logger.Errorf("[UPSTREAM] 所有 %s 服务器查询 %s 均失败", serverTypeToString(serverType), domain)
	return &Result{
		Err:  fmt.Errorf("all %s servers failed", serverTypeToString(serverType)),
		Type: serverType,
	}
}

// querySingle 查询单个服务器
func (m *Manager) querySingle(ctx context.Context, msg *dns.Msg, server string, serverType ServerType) *Result {
	start := time.Now()

	// 设置超时
	queryCtx, cancel := context.WithTimeout(ctx, m.timeout)
	defer cancel()

	// 使用channel进行异步查询
	respChan := make(chan *dns.Msg, 1)
	errChan := make(chan error, 1)

	go func() {
		r, _, err := m.client.Exchange(msg, server)
		if err != nil {
			errChan <- err
			return
		}
		respChan <- r
	}()

	select {
	case <-queryCtx.Done():
		return &Result{
			Err:       queryCtx.Err(),
			Server:    server,
			Type:      serverType,
			Duration:  time.Since(start),
			Timestamp: time.Now(),
		}
	case err := <-errChan:
		return &Result{
			Err:       err,
			Server:    server,
			Type:      serverType,
			Duration:  time.Since(start),
			Timestamp: time.Now(),
		}
	case r := <-respChan:
		// 检查DNS响应代码
		if r.Rcode != dns.RcodeSuccess {
			return &Result{
				Err:       fmt.Errorf("DNS response error: %s", dns.RcodeToString[r.Rcode]),
				Server:    server,
				Type:      serverType,
				Duration:  time.Since(start),
				Timestamp: time.Now(),
			}
		}
		return &Result{
			Response:  r,
			Server:    server,
			Type:      serverType,
			Duration:  time.Since(start),
			Timestamp: time.Now(),
		}
	}
}

// serverTypeToString 服务器类型转字符串
func serverTypeToString(t ServerType) string {
	switch t {
	case LocalServer:
		return "local"
	case OverseasServer:
		return "overseas"
	default:
		return "unknown"
	}
}

// GetLocalServers 获取本地服务器列表
func (m *Manager) GetLocalServers() []string {
	return m.localServers
}

// GetOverseasServers 获取海外服务器列表
func (m *Manager) GetOverseasServers() []string {
	return m.overseasServers
}

// generateCacheKey 生成缓存键
func (m *Manager) generateCacheKey(msg *dns.Msg) string {
	if len(msg.Question) > 0 {
		q := msg.Question[0]
		return fmt.Sprintf("%s|%d|%d", q.Name, q.Qtype, q.Qclass)
	}
	return fmt.Sprintf("%v", msg)
}

// getFromCache 从缓存获取结果（乐观缓存：过期也返回，后台更新）
func (m *Manager) getFromCache(key string) *Result {
	m.localCacheMu.RLock()
	defer m.localCacheMu.RUnlock()

	result, exists := m.localCache[key]
	if !exists {
		return nil
	}

	// 乐观缓存：即使过期也返回，后台更新
	// 不再检查缓存是否过期，直接返回
	return result
}

// saveToCache 保存结果到缓存
func (m *Manager) saveToCache(key string, result *Result) {
	m.localCacheMu.Lock()
	defer m.localCacheMu.Unlock()

	m.localCache[key] = result

	// 限制缓存大小，防止内存泄漏
	if len(m.localCache) > 10000 {
		// 简单清理：保留最新的5000个
		count := 0
		for k := range m.localCache {
			if count >= 5000 {
				delete(m.localCache, k)
			}
			count++
		}
	}
}
