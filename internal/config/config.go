package config

import (
	"fmt"
	"lo-dns/internal/logger"
	"os"

	"gopkg.in/yaml.v3"
)

// Config 总配置结构
type Config struct {
	BaseDir      string             `yaml:"base_dir"`
	Server       ServerConfig       `yaml:"server"`
	Upstream     UpstreamConfig     `yaml:"upstream"`
	LocalDomains LocalDomainsConfig `yaml:"local_domains"`
	PoisonCheck  PoisonCheckConfig  `yaml:"poison_check"`
}

// ServerConfig DNS服务器配置
type ServerConfig struct {
	Listen      string `yaml:"listen"`
	CacheSize   int    `yaml:"cache_size"`
	LogTimezone string `yaml:"log_timezone"`
	LogLevel    string `yaml:"log_level"`
	LogPath     string `yaml:"log_path"`
	CachePath   string `yaml:"cache_path"`
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
	Overpass       []string `yaml:"overpass"`
}

// PoisonCheckConfig 判毒检查配置
type PoisonCheckConfig struct {
	Enabled              bool   `yaml:"enabled"`
	TLSTimeout           int    `yaml:"tls_timeout"`
	ConcurrentChecks     int    `yaml:"concurrent_checks"`
	TLSPort              int    `yaml:"tls_port"`
	CacheRefreshInterval int    `yaml:"cache_refresh_interval"`
	CacheTTL             int    `yaml:"cache_ttl"` // 缓存过期时间（分钟）
	ASNEnabled           bool   `yaml:"asn_enabled"`
	ASNFilePath          string `yaml:"asn_file_path"`
	// ASNMergeIntervalHours 多源合并定时间隔（小时）；启动时仅当 cache 下合并文件不存在才自动合并一次，0 表示不轮询（可手动 asn-merge）
	ASNMergeIntervalHours int `yaml:"asn_merge_interval_hours"`
	// ASNMergeAppleRIPE 为 true 时将 RIPE 公布的 AS714 前缀并入 apple（列表可能很长）
	ASNMergeAppleRIPE bool `yaml:"asn_merge_apple_ripe"`
}

// GetLogLevel 将字符串日志等级转换为logger包中的等级常量
func GetLogLevel(level string) int {
	switch level {
	case "debug":
		return logger.Debug
	case "info":
		return logger.Info
	case "warn":
		return logger.Warn
	case "error":
		return logger.Error
	case "fatal":
		return logger.Fatal
	default:
		return logger.Info
	}
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
	if cfg.BaseDir == "" {
		currentDir, err := os.Getwd()
		if err != nil {
			currentDir = "."
		}
		cfg.BaseDir = currentDir
	}
	if cfg.Server.Listen == "" {
		cfg.Server.Listen = ":53"
	}
	if cfg.Server.CacheSize == 0 {
		cfg.Server.CacheSize = 10000
	}
	if cfg.Server.LogTimezone == "" {
		cfg.Server.LogTimezone = "Asia/Shanghai"
	}
	if cfg.Server.LogLevel == "" {
		cfg.Server.LogLevel = "info"
	}
	if cfg.Server.LogPath == "" {
		cfg.Server.LogPath = "log"
	}
	if cfg.Server.CachePath == "" {
		cfg.Server.CachePath = "cache"
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
	if cfg.PoisonCheck.CacheTTL == 0 {
		cfg.PoisonCheck.CacheTTL = 30
	}
	if cfg.PoisonCheck.ASNFilePath == "" {
		cfg.PoisonCheck.ASNFilePath = "data/domain_asn.json"
	}

	return &cfg, nil
}
