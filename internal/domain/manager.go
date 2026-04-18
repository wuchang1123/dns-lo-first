package domain

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Manager struct {
	config  Config
	domains map[string]struct{}
	mu      sync.RWMutex
}

type Config struct {
	SourceURL      string   `yaml:"source_url"`
	FilePath       string   `yaml:"file_path"`
	UpdateInterval int      `yaml:"update_interval"`
	Custom         []string `yaml:"custom"`
}

func NewManager(cfg Config) *Manager {
	return &Manager{
		config:  cfg,
		domains: make(map[string]struct{}),
	}
}

func (m *Manager) Load() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// 清空现有数据
	m.domains = make(map[string]struct{})

	// 加载自定义域名
	for _, domain := range m.config.Custom {
		m.domains[normalizeDomain(domain)] = struct{}{}
	}

	// 从文件加载
	if m.config.FilePath != "" {
		if err := m.loadFromFile(m.config.FilePath); err != nil {
			// 文件不存在时尝试更新
			fmt.Printf("加载域名文件失败: %v，将尝试更新\n", err)
		}
	}

	return nil
}

func (m *Manager) loadFromFile(filepath string) error {
	f, err := os.Open(filepath)
	if err != nil {
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// 处理 dnsmasq 格式: server=/domain1/domain2/domain3/.../ip
		// 新格式支持在一行中包含多个域名
		if strings.HasPrefix(line, "server=/") {
			parts := strings.Split(line, "/")
			// parts[0] = "server", parts[1..n-1] = domains, parts[n] = IP
			// 遍历所有域名段（最后一段是IP，跳过）
			for i := 1; i < len(parts)-1; i++ {
				domain := normalizeDomain(parts[i])
				if domain != "" {
					m.domains[domain] = struct{}{}
				}
			}
			continue
		}

		// 普通域名格式
		domain := normalizeDomain(line)
		if domain != "" {
			m.domains[domain] = struct{}{}
		}
	}

	return scanner.Err()
}

// Update 更新域名列表
func (m *Manager) Update() error {
	if m.config.SourceURL == "" {
		return nil
	}

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Get(m.config.SourceURL)
	if err != nil {
		return fmt.Errorf("下载域名列表失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	// 确保目录存在
	dir := getDir(m.config.FilePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	// 保存到临时文件
	tmpFile := m.config.FilePath + ".tmp"
	f, err := os.Create(tmpFile)
	if err != nil {
		return err
	}

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		f.WriteString(line + "\n")
	}
	f.Close()

	if err := scanner.Err(); err != nil {
		os.Remove(tmpFile)
		return err
	}

	// 原子替换
	if err := os.Rename(tmpFile, m.config.FilePath); err != nil {
		os.Remove(tmpFile)
		return err
	}

	// 重新加载
	return m.Load()
}

// IsLocalDomain 检查是否为所在国域名
func (m *Manager) IsLocalDomain(domain string) bool {
	domain = normalizeDomain(domain)

	m.mu.RLock()
	defer m.mu.RUnlock()

	// 精确匹配
	if _, ok := m.domains[domain]; ok {
		return true
	}

	// 检查父域名
	parts := strings.Split(domain, ".")
	for i := 1; i < len(parts); i++ {
		parent := strings.Join(parts[i:], ".")
		if _, ok := m.domains[parent]; ok {
			return true
		}
	}

	return false
}

// normalizeDomain 规范化域名
func normalizeDomain(domain string) string {
	domain = strings.ToLower(strings.TrimSpace(domain))
	domain = strings.TrimSuffix(domain, ".")
	return domain
}

// getDir 获取文件所在目录
func getDir(path string) string {
	dir, _ := filepath.Split(path)
	return dir
}

// GetDomainCount 获取域名数量
func (m *Manager) GetDomainCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.domains)
}
