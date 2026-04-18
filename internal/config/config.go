package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config 总配置结构
type Config struct {
	Server       ServerConfig       `yaml:"server"`
	Upstream     UpstreamConfig     `yaml:"upstream"`
	LocalDomains LocalDomainsConfig `yaml:"local_domains"`
	PoisonCheck  PoisonCheckConfig  `yaml:"poison_check"`
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

// LocalDomainsConfig 所在国域名配置
type LocalDomainsConfig struct {
	SourceURL      string   `yaml:"source_url"`
	FilePath       string   `yaml:"file_path"`
	UpdateInterval int      `yaml:"update_interval"`
	Custom         []string `yaml:"custom"`
}

// PoisonCheckConfig 判毒系统配置
type PoisonCheckConfig struct {
	Enabled              bool `yaml:"enabled"`
	TLSTimeout           int  `yaml:"tls_timeout"`
	ConcurrentChecks     int  `yaml:"concurrent_checks"`
	TLSPort              int  `yaml:"tls_port"`
	StrictMode           bool `yaml:"strict_mode"`
	CacheRefreshInterval int  `yaml:"cache_refresh_interval"`
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
	if cfg.PoisonCheck.CacheRefreshInterval == 0 {
		cfg.PoisonCheck.CacheRefreshInterval = 30
	}

	return &cfg, nil
}
