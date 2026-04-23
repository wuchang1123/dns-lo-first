package config

import (
	"fmt"
	"lo-dns/internal/logger"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Config 总配置结构
type Config struct {
	BaseDir      string             `yaml:"base_dir"`
	Server       ServerConfig       `yaml:"server"`
	Upstream     UpstreamConfig     `yaml:"upstream"`
	// BootstrapDNS HTTP 下载（所在国列表、ASN 合并等）解析 HTTPS 时使用的递归 DNS，形如 "223.5.5.5:53"。
	// 启动阶段本机可能尚无可用 DNS，不宜依赖系统 resolv。非空时仅使用本列表；为空则从 upstream 取非回环地址，再兜底公共 DNS。
	BootstrapDNS []string `yaml:"bootstrap_dns"`
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
	// CommonBlockedDomainsPath 常见受限/测试域名列表（纯文本，一行一域，# 开头为注释）。行首 *.example.com 按 RFC 4592 仅匹配其严格子域（不含 apex example.com）；无 * 的行匹配该名及任意子域。非空且文件可读时仅上述集合做 TLS 判毒，其余跳过并视为通过；留空则对所有域名判毒。
	CommonBlockedDomainsPath string `yaml:"common_blocked_domains_path"`
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
	// CommonBlockedDomainsPath 不设默认：留空表示对所有域名做 TLS 判毒；非空则仅对列表内域名判毒。

	return &cfg, nil
}

// ResolveDataPath 将 p 解析为绝对路径：空串返回空；已为绝对路径则规范化后返回；否则 filepath.Join(baseDir, p)。
func ResolveDataPath(baseDir, p string) string {
	if p == "" {
		return ""
	}
	if filepath.IsAbs(p) {
		return filepath.Clean(p)
	}
	return filepath.Join(baseDir, filepath.Clean(p))
}
