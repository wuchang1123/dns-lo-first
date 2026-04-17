package iprange

import (
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
)

// Manager IP段管理器
type Manager struct {
	ranges map[string][]*net.IPNet // service -> IP网段列表
	mu     sync.RWMutex
	config config.OverseasIPRangesConfig
}

// NewManager 创建IP段管理器
func NewManager(cfg config.OverseasIPRangesConfig) *Manager {
	return &Manager{
		ranges: make(map[string][]*net.IPNet),
		config: cfg,
	}
}

// Load 从文件加载IP段
func (m *Manager) Load() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// 加载自定义IP段
	for service, cidrs := range m.config.Custom {
		for _, cidr := range cidrs {
			_, ipnet, err := net.ParseCIDR(cidr)
			if err != nil {
				return fmt.Errorf("解析CIDR %s 失败: %w", cidr, err)
			}
			m.ranges[service] = append(m.ranges[service], ipnet)
		}
	}

	// 从文件加载
	for name, source := range m.config.Sources {
		if err := m.loadFromFile(name, source.FilePath); err != nil {
			// 文件不存在时尝试更新
			continue
		}
	}

	return nil
}

// loadFromFile 从文件加载IP段
func (m *Manager) loadFromFile(service, filepath string) error {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return err
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// 处理JSON格式（Google）
		if strings.HasPrefix(line, "{") {
			var result struct {
				Prefixes []struct {
					IPv4Prefix string `json:"ipv4Prefix"`
					IPv6Prefix string `json:"ipv6Prefix"`
				} `json:"prefixes"`
			}
			if err := json.Unmarshal([]byte(line), &result); err == nil {
				for _, p := range result.Prefixes {
					if p.IPv4Prefix != "" {
						_, ipnet, _ := net.ParseCIDR(p.IPv4Prefix)
						if ipnet != nil {
							m.ranges[service] = append(m.ranges[service], ipnet)
						}
					}
				}
			}
			continue
		}

		// 处理纯CIDR格式
		_, ipnet, err := net.ParseCIDR(line)
		if err == nil {
			m.ranges[service] = append(m.ranges[service], ipnet)
		}
	}

	return nil
}

// Update 更新IP段数据
func (m *Manager) Update() error {
	for name, source := range m.config.Sources {
		if err := m.downloadAndSave(name, source); err != nil {
			fmt.Printf("更新 %s IP段失败: %v\n", name, err)
		}
	}
	return m.Load()
}

// downloadAndSave 下载并保存IP段
func (m *Manager) downloadAndSave(name string, source config.IPRangeSource) error {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(source.URL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	// 确保目录存在
	dir := filepath.Dir(source.FilePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	// 保存到临时文件
	tmpFile := source.FilePath + ".tmp"
	f, err := os.Create(tmpFile)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err := f.ReadFrom(resp.Body); err != nil {
		os.Remove(tmpFile)
		return err
	}
	f.Close()

	// 原子替换
	return os.Rename(tmpFile, source.FilePath)
}

// Contains 检查IP是否属于指定服务的IP段
func (m *Manager) Contains(service string, ip net.IP) bool {
	m.mu.RLock()
	nets, ok := m.ranges[service]
	m.mu.RUnlock()

	if !ok {
		return false
	}

	for _, ipnet := range nets {
		if ipnet.Contains(ip) {
			return true
		}
	}
	return false
}

// FindService 查找IP属于哪个服务
func (m *Manager) FindService(ip net.IP) string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for service, nets := range m.ranges {
		for _, ipnet := range nets {
			if ipnet.Contains(ip) {
				return service
			}
		}
	}
	return ""
}

// IsInAnyRange 检查IP是否在任何已知的海外服务IP段中
func (m *Manager) IsInAnyRange(ip net.IP) bool {
	return m.FindService(ip) != ""
}

// GetAllServices 获取所有服务名称
func (m *Manager) GetAllServices() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	services := make([]string, 0, len(m.ranges))
	for service := range m.ranges {
		services = append(services, service)
	}
	return services
}
