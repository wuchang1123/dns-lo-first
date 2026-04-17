package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config 总配置结构
type Config struct {
	Server           ServerConfig           `yaml:"server"`
	Upstream         UpstreamConfig         `yaml:"upstream"`
	ChinaDomains     ChinaDomainsConfig     `yaml:"china_domains"`
	OverseasIPRanges OverseasIPRangesConfig `yaml:"overseas_ip_ranges"`
	PoisonCheck      PoisonCheckConfig      `yaml:"poison_check"`
}

// ServerConfig DNS服务器配置
type ServerConfig struct {
	Listen    string `yaml:"listen"`
	CacheSize int    `yaml:"cache_size"`
}

// UpstreamConfig 上游服务器配置
type UpstreamConfig struct {
	Local    []string `yaml:"local"`
	Overseas []string `yaml:"overseas"`
}

// ChinaDomainsConfig 中国域名配置
type ChinaDomainsConfig struct {
	SourceURL      string   `yaml:"source_url"`
	FilePath       string   `yaml:"file_path"`
	UpdateInterval int      `yaml:"update_interval"`
	Custom         []string `yaml:"custom"`
}

// OverseasIPRangesConfig 海外IP段配置
type OverseasIPRangesConfig struct {
	Sources map[string]IPRangeSource `yaml:"sources"`
	Custom  map[string][]string      `yaml:"custom"`
}

// IPRangeSource IP段数据源
type IPRangeSource struct {
	URL            string `yaml:"url"`
	FilePath       string `yaml:"file_path"`
	UpdateInterval int    `yaml:"update_interval"`
}

// PoisonCheckConfig 判毒系统配置
type PoisonCheckConfig struct {
	Enabled          bool `yaml:"enabled"`
	TLSTimeout       int  `yaml:"tls_timeout"`
	ConcurrentChecks int  `yaml:"concurrent_checks"`
	TLSPort          int  `yaml:"tls_port"`
	StrictMode       bool `yaml:"strict_mode"`
}

// Load 加载配置文件
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取配置文件失败: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("解析配置文件失败: %w", err)
	}

	// 设置默认值
	if cfg.Server.Listen == "" {
		cfg.Server.Listen = ":53"
	}
	if cfg.Server.CacheSize == 0 {
		cfg.Server.CacheSize = 10000
	}
	if cfg.PoisonCheck.TLSTimeout == 0 {
		cfg.PoisonCheck.TLSTimeout = 5
	}
	if cfg.PoisonCheck.ConcurrentChecks == 0 {
		cfg.PoisonCheck.ConcurrentChecks = 10
	}
	if cfg.PoisonCheck.TLSPort == 0 {
		cfg.PoisonCheck.TLSPort = 443
	}

	return &cfg, nil
}
