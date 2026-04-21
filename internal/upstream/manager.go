package upstream

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
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

	// 检查是否为HTTPS DNS服务器
	if strings.HasPrefix(server, "https://") {
		return m.queryHTTPS(ctx, msg, server, serverType, time.Since(start))
	}

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
	// 提取IP地址或域名
	var ipStr string

	// 处理HTTPS URL
	if strings.HasPrefix(server, "https://") {
		// 解析URL，提取域名
		url := server
		// 去掉https://前缀
		host := strings.TrimPrefix(url, "https://")
		// 提取域名部分（去掉路径）
		if idx := strings.Index(host, "/"); idx != -1 {
			host = host[:idx]
		}
		ipStr = host
	} else {
		// 处理普通服务器地址（IP:端口）
		var err error
		ipStr, _, err = net.SplitHostPort(server)
		if err != nil {
			// 如果没有端口，直接使用server作为IP
			ipStr = server
		}
	}

	// 尝试ping服务器
	addr, err := net.ResolveIPAddr("ip", ipStr)
	if err != nil {
		// 如果解析失败，尝试解析域名
		addrs, err := net.LookupHost(ipStr)
		if err != nil || len(addrs) == 0 {
			return false
		}
		ipStr = addrs[0]
		addr, err = net.ResolveIPAddr("ip", ipStr)
		if err != nil {
			return false
		}
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

// queryHTTPS 查询HTTPS DNS服务器
func (m *Manager) queryHTTPS(ctx context.Context, msg *dns.Msg, server string, serverType ServerType, duration time.Duration) *Result {
	// 设置超时
	queryCtx, cancel := context.WithTimeout(ctx, m.timeout)
	defer cancel()

	httpClient := &http.Client{
		Timeout: m.timeout,
	}

	// 检查是否为JSON API
	if strings.Contains(server, "/resolve") {
		return m.queryHTTPSJSON(queryCtx, msg, server, serverType, httpClient, duration)
	}

	// 否则使用RFC 8484 (DoH)
	return m.queryHTTPSDoH(queryCtx, msg, server, serverType, httpClient, duration)
}

// queryHTTPSDoH 使用RFC 8484查询HTTPS DNS
func (m *Manager) queryHTTPSDoH(ctx context.Context, msg *dns.Msg, server string, serverType ServerType, client *http.Client, duration time.Duration) *Result {
	// 编码DNS消息
	buf, err := msg.Pack()
	if err != nil {
		return &Result{
			Err:      fmt.Errorf("failed to pack DNS message: %v", err),
			Server:   server,
			Type:     serverType,
			Duration: duration + time.Since(time.Now()),
		}
	}

	// 构建请求
	req, err := http.NewRequestWithContext(ctx, "GET", server, nil)
	if err != nil {
		return &Result{
			Err:      fmt.Errorf("failed to create request: %v", err),
			Server:   server,
			Type:     serverType,
			Duration: duration + time.Since(time.Now()),
		}
	}

	// 添加必要的头
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("Content-Type", "application/dns-message")

	// 将DNS消息作为base64url编码的查询参数
	encoded := base64.RawURLEncoding.EncodeToString(buf)
	query := req.URL.Query()
	query.Add("dns", encoded)
	req.URL.RawQuery = query.Encode()

	// 发送请求
	resp, err := client.Do(req)
	if err != nil {
		return &Result{
			Err:      fmt.Errorf("HTTP request failed: %v", err),
			Server:   server,
			Type:     serverType,
			Duration: duration + time.Since(time.Now()),
		}
	}
	defer resp.Body.Close()

	// 检查响应状态
	if resp.StatusCode != http.StatusOK {
		return &Result{
			Err:      fmt.Errorf("HTTP error: %s", resp.Status),
			Server:   server,
			Type:     serverType,
			Duration: duration + time.Since(time.Now()),
		}
	}

	// 读取响应
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return &Result{
			Err:      fmt.Errorf("failed to read response: %v", err),
			Server:   server,
			Type:     serverType,
			Duration: duration + time.Since(time.Now()),
		}
	}

	// 解析DNS响应
	responseMsg := &dns.Msg{}
	if err := responseMsg.Unpack(body); err != nil {
		return &Result{
			Err:      fmt.Errorf("failed to unpack DNS response: %v", err),
			Server:   server,
			Type:     serverType,
			Duration: duration + time.Since(time.Now()),
		}
	}

	return &Result{
		Response: responseMsg,
		Server:   server,
		Type:     serverType,
		Duration: duration + time.Since(time.Now()),
	}
}

// queryHTTPSJSON 使用JSON API查询HTTPS DNS
func (m *Manager) queryHTTPSJSON(ctx context.Context, msg *dns.Msg, server string, serverType ServerType, client *http.Client, duration time.Duration) *Result {
	// 提取查询信息
	if len(msg.Question) == 0 {
		return &Result{
			Err:      fmt.Errorf("no questions in DNS message"),
			Server:   server,
			Type:     serverType,
			Duration: duration + time.Since(time.Now()),
		}
	}

	q := msg.Question[0]

	// 构建请求URL
	req, err := http.NewRequestWithContext(ctx, "GET", server, nil)
	if err != nil {
		return &Result{
			Err:      fmt.Errorf("failed to create request: %v", err),
			Server:   server,
			Type:     serverType,
			Duration: duration + time.Since(time.Now()),
		}
	}

	// 添加查询参数
	query := req.URL.Query()
	query.Add("name", q.Name)
	query.Add("type", fmt.Sprintf("%d", q.Qtype))
	req.URL.RawQuery = query.Encode()

	// 发送请求
	resp, err := client.Do(req)
	if err != nil {
		return &Result{
			Err:      fmt.Errorf("HTTP request failed: %v", err),
			Server:   server,
			Type:     serverType,
			Duration: duration + time.Since(time.Now()),
		}
	}
	defer resp.Body.Close()

	// 检查响应状态
	if resp.StatusCode != http.StatusOK {
		return &Result{
			Err:      fmt.Errorf("HTTP error: %s", resp.Status),
			Server:   server,
			Type:     serverType,
			Duration: duration + time.Since(time.Now()),
		}
	}

	// 读取响应
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return &Result{
			Err:      fmt.Errorf("failed to read response: %v", err),
			Server:   server,
			Type:     serverType,
			Duration: duration + time.Since(time.Now()),
		}
	}

	// 解析JSON响应
	var jsonResp struct {
		Status int `json:"Status"`
		Answer []struct {
			Name string `json:"name"`
			Type int    `json:"type"`
			TTL  int    `json:"TTL"`
			Data string `json:"data"`
		} `json:"Answer"`
	}

	if err := json.Unmarshal(body, &jsonResp); err != nil {
		return &Result{
			Err:      fmt.Errorf("failed to parse JSON response: %v", err),
			Server:   server,
			Type:     serverType,
			Duration: duration + time.Since(time.Now()),
		}
	}

	// 构建DNS响应
	responseMsg := &dns.Msg{}
	responseMsg.SetReply(msg)
	responseMsg.Rcode = jsonResp.Status

	// 添加回答
	for _, ans := range jsonResp.Answer {
		var rr dns.RR
		switch uint16(ans.Type) {
		case dns.TypeA:
			rr, err = dns.NewRR(fmt.Sprintf("%s %d IN A %s", ans.Name, ans.TTL, ans.Data))
		case dns.TypeAAAA:
			rr, err = dns.NewRR(fmt.Sprintf("%s %d IN AAAA %s", ans.Name, ans.TTL, ans.Data))
		case dns.TypeCNAME:
			rr, err = dns.NewRR(fmt.Sprintf("%s %d IN CNAME %s", ans.Name, ans.TTL, ans.Data))
		default:
			continue
		}
		if err == nil {
			responseMsg.Answer = append(responseMsg.Answer, rr)
		}
	}

	return &Result{
		Response: responseMsg,
		Server:   server,
		Type:     serverType,
		Duration: duration + time.Since(time.Now()),
	}
}
