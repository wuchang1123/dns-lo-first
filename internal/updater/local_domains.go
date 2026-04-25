package updater

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"dns-lo-first/internal/config"
	"dns-lo-first/internal/logger"
)

type LocalDomainUpdater struct {
	cfg       *config.Config
	log       *logger.Logger
	onUpdated func() error
}

func NewLocalDomainUpdater(cfg *config.Config, log *logger.Logger, onUpdated func() error) *LocalDomainUpdater {
	return &LocalDomainUpdater{cfg: cfg, log: log, onUpdated: onUpdated}
}

func (u *LocalDomainUpdater) Start(ctx context.Context) {
	if u.cfg.LocalDomains.SourceURL == "" || u.cfg.LocalDomains.FilePath == "" {
		return
	}
	go func() {
		u.update(ctx)
		ticker := time.NewTicker(u.cfg.LocalDomainUpdateInterval())
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				u.update(ctx)
			case <-ctx.Done():
				return
			}
		}
	}()
}

func (u *LocalDomainUpdater) update(ctx context.Context) {
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout: 10 * time.Second,
				Resolver: &net.Resolver{
					PreferGo: true,
					Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
						d := net.Dialer{Timeout: 5 * time.Second}
						return d.DialContext(ctx, "udp", u.cfg.BootstrapServers()[0])
					},
				},
			}).DialContext,
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.cfg.LocalDomains.SourceURL, nil)
	if err != nil {
		u.log.Warnf("build local domain update request failed: %v", err)
		return
	}
	resp, err := client.Do(req)
	if err != nil {
		u.log.Warnf("update local domains failed: %v", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		u.log.Warnf("update local domains returned http %d", resp.StatusCode)
		return
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		u.log.Warnf("read local domains failed: %v", err)
		return
	}
	if err := os.MkdirAll(filepath.Dir(u.cfg.LocalDomains.FilePath), 0o755); err != nil {
		u.log.Warnf("create local domain dir failed: %v", err)
		return
	}
	tmp := u.cfg.LocalDomains.FilePath + ".tmp"
	if err := os.WriteFile(tmp, body, 0o644); err != nil {
		u.log.Warnf("write local domains failed: %v", err)
		return
	}
	if err := os.Rename(tmp, u.cfg.LocalDomains.FilePath); err != nil {
		u.log.Warnf("replace local domains failed: %v", err)
		return
	}
	u.log.Infof("updated local domain list: %s", u.cfg.LocalDomains.FilePath)
	if u.onUpdated != nil {
		if err := u.onUpdated(); err != nil {
			u.log.Warnf("reload local domains failed: %v", err)
		}
	}
}
