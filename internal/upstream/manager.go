package upstream

import (
	"context"
	"fmt"
	"net"
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
	Response *dns.Msg
	Server   string
	Type     ServerType
	Err      error
	Duration time.Duration
}

// Manager 上游服务器管理器
type Manager struct {
	localServers    []string
	overseasServers []string
	client          *dns.Client
	timeout         time.Duration
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
		timeout: 5 * time.Second,
	}
}

// QueryLocal 查询本地DNS
func (m *Manager) QueryLocal(ctx context.Context, msg *dns.Msg) *Result {
	return m.queryServers(ctx, msg, m.localServers, LocalServer)
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
				logger.Errorf("[UPSTREAM] %s 服务器 %s 查询失败: %v", serverTypeToString(serverType), srv, result.Err)

				// 当海外服务器失败时，尝试ping测试
				if serverType == OverseasServer {
					go func() {
						pingResult := pingServer(srv)
						if pingResult {
							logger.Infof("[UPSTREAM] %s 服务器 %s ping 测试成功", serverTypeToString(serverType), srv)
						} else {
							logger.Warnf("[UPSTREAM] %s 服务器 %s ping 测试失败", serverTypeToString(serverType), srv)
						}
					}()
				}
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
	logger.Errorf("[UPSTREAM] 所有 %s 服务器均查询失败", serverTypeToString(serverType))
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
			Err:      queryCtx.Err(),
			Server:   server,
			Type:     serverType,
			Duration: time.Since(start),
		}
	case err := <-errChan:
		return &Result{
			Err:      err,
			Server:   server,
			Type:     serverType,
			Duration: time.Since(start),
		}
	case r := <-respChan:
		// 检查DNS响应代码
		if r.Rcode != dns.RcodeSuccess {
			return &Result{
				Err:      fmt.Errorf("DNS response error: %s", dns.RcodeToString[r.Rcode]),
				Server:   server,
				Type:     serverType,
				Duration: time.Since(start),
			}
		}
		return &Result{
			Response: r,
			Server:   server,
			Type:     serverType,
			Duration: time.Since(start),
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

// pingServer 测试服务器连通性
func pingServer(server string) bool {
	// 提取IP地址（去掉端口）
	ipStr, _, err := net.SplitHostPort(server)
	if err != nil {
		// 如果没有端口，直接使用server作为IP
		ipStr = server
	}

	// 尝试ping服务器
	addr, err := net.ResolveIPAddr("ip", ipStr)
	if err != nil {
		return false
	}

	conn, err := net.DialTimeout("ip4:icmp", addr.String(), 2*time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()

	// 发送ping包
	message := []byte{8, 0, 0, 0, 0, 0, 0, 0}
	_, err = conn.Write(message)
	if err != nil {
		return false
	}

	// 等待响应
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1024)
	_, err = conn.Read(buf)
	return err == nil
}

// GetLocalServers 获取本地服务器列表
func (m *Manager) GetLocalServers() []string {
	return m.localServers
}

// GetOverseasServers 获取海外服务器列表
func (m *Manager) GetOverseasServers() []string {
	return m.overseasServers
}
