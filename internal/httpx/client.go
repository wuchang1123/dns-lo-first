// Package httpx 提供带自定义 DNS 解析的 HTTP 客户端，用于启动阶段 HTTPS 下载（避免系统 resolv 指向不可用地址）。
package httpx

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"strings"
	"time"
)

// EffectiveResolvers 与 NewHTTPClient(nameservers, _) 实际用于解析的 Do53 列表一致（规范化后仍为空则用内置公共 DNS）。
func EffectiveResolvers(nameservers []string) []string {
	ns := NormalizeNameservers(append([]string(nil), nameservers...))
	if len(ns) == 0 {
		return []string{"223.5.5.5:53", "8.8.8.8:53", "1.1.1.1:53"}
	}
	return ns
}

// NewHTTPClient 使用 nameservers（Do53，形如 host:port）解析 HTTPS 主机名；列表为空时使用兜底公共 DNS。
func NewHTTPClient(nameservers []string, timeout time.Duration) *http.Client {
	ns := EffectiveResolvers(nameservers)
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		Resolver: &net.Resolver{
			PreferGo: true,
			Dial:     rotatingDNSDial(ns),
		},
	}
	tr := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   15 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
	}
	return &http.Client{Transport: tr, Timeout: timeout}
}

func rotatingDNSDial(nameservers []string) func(ctx context.Context, network, address string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		d := net.Dialer{Timeout: 8 * time.Second}
		var last error
		for _, ns := range nameservers {
			c, err := d.DialContext(ctx, network, ns)
			if err == nil {
				return c, nil
			}
			last = err
		}
		if last != nil {
			return nil, last
		}
		return nil, context.Canceled
	}
}

// NormalizeNameservers 规范化并去重，补全 :53，过滤回环地址。
func NormalizeNameservers(addrs []string) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, raw := range addrs {
		addr := normalizeOneNS(raw)
		if addr == "" || !usableNameserver(addr) {
			continue
		}
		if _, ok := seen[addr]; ok {
			continue
		}
		seen[addr] = struct{}{}
		out = append(out, addr)
	}
	return out
}

func normalizeOneNS(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	host, port, err := net.SplitHostPort(raw)
	if err != nil {
		return net.JoinHostPort(raw, "53")
	}
	if port == "" {
		return net.JoinHostPort(host, "53")
	}
	return net.JoinHostPort(host, port)
}

func usableNameserver(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	if ip == nil {
		return true
	}
	return !ip.IsLoopback()
}

// NameserversFromUpstream 从 upstream 配置合并本地与海外 DNS，去回环；可与 BootstrapDNS 二选一使用。
func NameserversFromUpstream(local, overseas []string) []string {
	return NormalizeNameservers(append(append([]string{}, local...), overseas...))
}

// NameserversForDownload bootstrapDNS 非空且规范化后仍非空时仅用该项；否则使用 upstream 本地+海外。结果再交给 NewHTTPClient（仍为空则内置公共 DNS）。
func NameserversForDownload(bootstrapDNS, local, overseas []string) []string {
	ns := NormalizeNameservers(append([]string(nil), bootstrapDNS...))
	if len(ns) > 0 {
		return ns
	}
	return NameserversFromUpstream(local, overseas)
}
