package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

type config struct {
	Server struct {
		Listen       string `yaml:"listen"`
		TotalTimeout string `yaml:"total_timeout"`
		Timezone     string `yaml:"timezone"`
	} `yaml:"server"`
	BootstrapDNS    []string `yaml:"bootstrap_dns"`
	DoHBootstrapDNS []string `yaml:"doh_bootstrap_dns"`
	Upstream        struct {
		Timeout               string `yaml:"timeout"`
		FreezeDuration        string `yaml:"freeze_duration"`
		LowScoreProbeInterval string `yaml:"low_score_probe_interval"`
		ECS                   struct {
			Enabled      bool   `yaml:"enabled"`
			IPv4         string `yaml:"ipv4"`
			SourcePrefix uint8  `yaml:"source_prefix"`
			ScopePrefix  uint8  `yaml:"scope_prefix"`
		} `yaml:"ecs"`
		Scoring struct {
			InitialScore            float64 `yaml:"initial_score"`
			MinScore                float64 `yaml:"min_score"`
			MaxScore                float64 `yaml:"max_score"`
			SuccessReward           float64 `yaml:"success_reward"`
			FailurePenalty          float64 `yaml:"failure_penalty"`
			TimeoutPenalty          float64 `yaml:"timeout_penalty"`
			LatencyPenaltyPer100ms  float64 `yaml:"latency_penalty_per_100ms"`
			OverseasLatencyDiscount float64 `yaml:"overseas_latency_discount"`
		} `yaml:"scoring"`
		Local    []string `yaml:"local"`
		Overseas []string `yaml:"overseas"`
	} `yaml:"upstream"`
	Cache struct {
		Response struct {
			Enabled     bool   `yaml:"enabled"`
			FilePath    string `yaml:"file_path"`
			MaxEntries  int    `yaml:"max_entries"`
			StaleTTL    string `yaml:"stale_ttl"`
			NXDomainTTL string `yaml:"nxdomain_ttl"`
		} `yaml:"response"`
		ResponseResult struct {
			Enabled    bool   `yaml:"enabled"`
			FilePath   string `yaml:"file_path"`
			MaxEntries int    `yaml:"max_entries"`
			IPIdleDays int    `yaml:"ip_idle_days"`
		} `yaml:"response_result"`
	} `yaml:"cache"`
	Routing struct {
		LocalOnly   []string `yaml:"local_only"`
		LocalDomain struct {
			SourceURL           string `yaml:"source_url"`
			FilePath            string `yaml:"file_path"`
			UpdateIntervalHours int    `yaml:"update_interval_hours"`
		} `yaml:"local_domains"`
	} `yaml:"routing"`
	Log struct {
		Level        string `yaml:"level"`
		Dir          string `yaml:"dir"`
		QueryFile    string `yaml:"query_file"`
		CleanupHours int    `yaml:"cleanup_hours"`
	} `yaml:"log"`
}

type runtimeConfig struct {
	config
	totalTimeout          time.Duration
	upstreamTimeout       time.Duration
	freezeDuration        time.Duration
	lowScoreProbeInterval time.Duration
	staleTTL              time.Duration
	nxdomainTTL           time.Duration
	location              *time.Location
}

func loadConfig(path string) (*runtimeConfig, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg runtimeConfig
	if err := yaml.Unmarshal(b, &cfg.config); err != nil {
		return nil, err
	}
	applyDefaults(&cfg)

	cfg.totalTimeout, err = time.ParseDuration(cfg.Server.TotalTimeout)
	if err != nil {
		return nil, fmt.Errorf("server.total_timeout: %w", err)
	}
	cfg.upstreamTimeout, err = time.ParseDuration(cfg.Upstream.Timeout)
	if err != nil {
		return nil, fmt.Errorf("upstream.timeout: %w", err)
	}
	cfg.freezeDuration, err = time.ParseDuration(cfg.Upstream.FreezeDuration)
	if err != nil {
		return nil, fmt.Errorf("upstream.freeze_duration: %w", err)
	}
	cfg.lowScoreProbeInterval, err = time.ParseDuration(cfg.Upstream.LowScoreProbeInterval)
	if err != nil {
		return nil, fmt.Errorf("upstream.low_score_probe_interval: %w", err)
	}
	cfg.staleTTL, err = time.ParseDuration(cfg.Cache.Response.StaleTTL)
	if err != nil {
		return nil, fmt.Errorf("cache.response.stale_ttl: %w", err)
	}
	cfg.nxdomainTTL, err = time.ParseDuration(cfg.Cache.Response.NXDomainTTL)
	if err != nil {
		return nil, fmt.Errorf("cache.response.nxdomain_ttl: %w", err)
	}
	cfg.location, err = time.LoadLocation(cfg.Server.Timezone)
	if err != nil {
		return nil, fmt.Errorf("server.timezone: %w", err)
	}
	return &cfg, nil
}

func applyDefaults(cfg *runtimeConfig) {
	if cfg.Server.Listen == "" {
		cfg.Server.Listen = ":53"
	}
	if cfg.Server.TotalTimeout == "" {
		cfg.Server.TotalTimeout = "6s"
	}
	if cfg.Server.Timezone == "" {
		cfg.Server.Timezone = "Asia/Shanghai"
	}
	if cfg.Upstream.Timeout == "" {
		cfg.Upstream.Timeout = "3s"
	}
	if cfg.Upstream.FreezeDuration == "" {
		cfg.Upstream.FreezeDuration = "1m"
	}
	if cfg.Upstream.LowScoreProbeInterval == "" {
		cfg.Upstream.LowScoreProbeInterval = "1h"
	}
	if cfg.Upstream.Scoring.InitialScore == 0 {
		cfg.Upstream.Scoring.InitialScore = 100
	}
	if cfg.Upstream.Scoring.MaxScore == 0 {
		cfg.Upstream.Scoring.MaxScore = 200
	}
	if cfg.Upstream.Scoring.SuccessReward == 0 {
		cfg.Upstream.Scoring.SuccessReward = 3
	}
	if cfg.Upstream.Scoring.FailurePenalty == 0 {
		cfg.Upstream.Scoring.FailurePenalty = 12
	}
	if cfg.Upstream.Scoring.TimeoutPenalty == 0 {
		cfg.Upstream.Scoring.TimeoutPenalty = 18
	}
	if cfg.Upstream.Scoring.LatencyPenaltyPer100ms == 0 {
		cfg.Upstream.Scoring.LatencyPenaltyPer100ms = 1
	}
	if cfg.Upstream.Scoring.OverseasLatencyDiscount == 0 {
		cfg.Upstream.Scoring.OverseasLatencyDiscount = 0.6
	}
	if cfg.Cache.Response.FilePath == "" {
		cfg.Cache.Response.FilePath = "./cache/response_cache.json"
	}
	if cfg.Cache.Response.MaxEntries == 0 {
		cfg.Cache.Response.MaxEntries = 50000
	}
	if cfg.Cache.Response.StaleTTL == "" {
		cfg.Cache.Response.StaleTTL = "3s"
	}
	if cfg.Cache.Response.NXDomainTTL == "" {
		cfg.Cache.Response.NXDomainTTL = "30s"
	}
	if cfg.Cache.ResponseResult.FilePath == "" {
		cfg.Cache.ResponseResult.FilePath = "./cache/response_result_cache.json"
	}
	if cfg.Cache.ResponseResult.MaxEntries == 0 {
		cfg.Cache.ResponseResult.MaxEntries = 50000
	}
	if cfg.Cache.ResponseResult.IPIdleDays == 0 {
		cfg.Cache.ResponseResult.IPIdleDays = 30
	}
	if cfg.Routing.LocalDomain.UpdateIntervalHours == 0 {
		cfg.Routing.LocalDomain.UpdateIntervalHours = 24
	}
	if cfg.Log.Dir == "" {
		cfg.Log.Dir = "./logs"
	}
	if cfg.Log.QueryFile == "" {
		cfg.Log.QueryFile = filepath.Join(cfg.Log.Dir, "query.log")
	}
	if cfg.Log.CleanupHours == 0 {
		cfg.Log.CleanupHours = 48
	}
}
