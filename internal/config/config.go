package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	BaseDir      string        `yaml:"base_dir"`
	BootstrapDNS []string      `yaml:"bootstrap_dns"`
	Server       Server        `yaml:"server"`
	Upstream     Upstream      `yaml:"upstream"`
	LocalDomains LocalDomains  `yaml:"local_domains"`
	KeySuspect   []DomainGroup `yaml:"key_suspect"`
	PoisonCheck  PoisonCheck   `yaml:"poison_check"`
}

type Server struct {
	Listen            string `yaml:"listen"`
	DomainTTL         uint32 `yaml:"domain_ttl"`
	ConcurrentTimeout int    `yaml:"concurrent_timeout"`
	LogTimezone       string `yaml:"log_timezone"`
	LogLevel          string `yaml:"log_level"`
	LogPath           string `yaml:"log_path"`
	CachePath         string `yaml:"cache_path"`
	CacheSize         int    `yaml:"cache_size"`
}

type Upstream struct {
	Servers      UpstreamServers `yaml:"servers"`
	LocalOnly    []string        `yaml:"local_only"`
	OverseasOnly []string        `yaml:"overseas_only"`
}

type UpstreamServers struct {
	Local    []string `yaml:"local"`
	Overseas []string `yaml:"overseas"`
}

type LocalDomains struct {
	SourceURL      string `yaml:"source_url"`
	FilePath       string `yaml:"file_path"`
	UpdateInterval int    `yaml:"update_interval"`
}

type DomainGroup struct {
	Domains []string `yaml:"domains"`
}

type PoisonCheck struct {
	Enabled          bool   `yaml:"enabled"`
	TLSTimeout       int    `yaml:"tls_timeout"`
	ConcurrentChecks int    `yaml:"concurrent_checks"`
	TLSPort          int    `yaml:"tls_port"`
	ASNEnabled       bool   `yaml:"asn_enabled"`
	ASNFilePath      string `yaml:"asn_file_path"`
}

func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return nil, err
	}
	cfg.applyDefaults()
	if cfg.Upstream.Servers.Empty() {
		return nil, errors.New("at least one upstream server is required")
	}
	if !filepath.IsAbs(cfg.BaseDir) {
		base, err := filepath.Abs(filepath.Dir(path))
		if err != nil {
			return nil, err
		}
		cfg.BaseDir = filepath.Join(base, cfg.BaseDir)
	}
	cfg.normalizePaths()
	return &cfg, nil
}

func (c *Config) applyDefaults() {
	if c.BaseDir == "" {
		c.BaseDir = "."
	}
	if c.Server.Listen == "" {
		c.Server.Listen = ":5355"
	}
	if c.Server.DomainTTL == 0 {
		c.Server.DomainTTL = 60
	}
	if c.Server.ConcurrentTimeout <= 0 {
		c.Server.ConcurrentTimeout = 6
	}
	if c.Server.LogTimezone == "" {
		c.Server.LogTimezone = "Asia/Shanghai"
	}
	if c.Server.LogLevel == "" {
		c.Server.LogLevel = "info"
	}
	if c.Server.LogPath == "" {
		c.Server.LogPath = "./log"
	}
	if c.Server.CachePath == "" {
		c.Server.CachePath = "./cache"
	}
	if c.Server.CacheSize <= 0 {
		c.Server.CacheSize = 10000
	}
	if c.LocalDomains.UpdateInterval <= 0 {
		c.LocalDomains.UpdateInterval = 24
	}
	if c.PoisonCheck.TLSTimeout <= 0 {
		c.PoisonCheck.TLSTimeout = 5
	}
	if c.PoisonCheck.ConcurrentChecks <= 0 {
		c.PoisonCheck.ConcurrentChecks = 10
	}
	if c.PoisonCheck.TLSPort <= 0 {
		c.PoisonCheck.TLSPort = 443
	}
	if c.PoisonCheck.ASNFilePath == "" {
		c.PoisonCheck.ASNFilePath = "./data/domain_asn.yaml"
	}
}

func (c *Config) normalizePaths() {
	c.Server.LogPath = c.Abs(c.Server.LogPath)
	c.Server.CachePath = c.Abs(c.Server.CachePath)
	c.LocalDomains.FilePath = c.Abs(c.LocalDomains.FilePath)
	c.PoisonCheck.ASNFilePath = c.Abs(c.PoisonCheck.ASNFilePath)
}

func (c *Config) Abs(path string) string {
	if path == "" || filepath.IsAbs(path) {
		return path
	}
	return filepath.Clean(filepath.Join(c.BaseDir, path))
}

func (s UpstreamServers) Empty() bool {
	return len(s.Local) == 0 && len(s.Overseas) == 0
}

func (c *Config) KeySuspectDomains() []string {
	var out []string
	for _, g := range c.KeySuspect {
		out = append(out, g.Domains...)
	}
	return out
}

func (c *Config) BootstrapServers() []string {
	if len(c.BootstrapDNS) > 0 {
		return c.BootstrapDNS
	}
	var out []string
	for _, s := range append(append([]string{}, c.Upstream.Servers.Local...), c.Upstream.Servers.Overseas...) {
		if !strings.HasPrefix(s, "127.") && !strings.HasPrefix(s, "[::1]") && !strings.HasPrefix(s, "::1") {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		out = []string{"223.5.5.5:53", "8.8.8.8:53", "1.1.1.1:53"}
	}
	return out
}

func (c *Config) LocalDomainUpdateInterval() time.Duration {
	return time.Duration(c.LocalDomains.UpdateInterval) * time.Hour
}
