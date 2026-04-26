package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"syscall"
	"time"

	"dns-lo-first/internal/asn"
	"dns-lo-first/internal/config"
	"dns-lo-first/internal/logger"
	"dns-lo-first/internal/poison"
	"dns-lo-first/internal/server"
	"dns-lo-first/internal/updater"
)

func main() {
	configPath := flag.String("config", "config.yaml", "path to config.yaml")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		panic(err)
	}
	log, err := logger.New(cfg.Server.LogLevel, cfg.Server.LogTimezone, cfg.Server.LogPath)
	if err != nil {
		panic(err)
	}
	defer log.Close()

	var asnDB *asn.DB
	if cfg.PoisonCheck.Enabled && cfg.PoisonCheck.ASNEnabled {
		asnDB, err = asn.Load(cfg.PoisonCheck.ASNFilePath)
		if err != nil {
			log.Fatalf("load ASN file failed: %v", err)
		}
		log.Infof("loaded ASN file: %s", cfg.PoisonCheck.ASNFilePath)
	}
	checker := poison.New(
		asnDB,
		cfg.PoisonCheck.Enabled,
		cfg.PoisonCheck.ASNEnabled,
		cfg.PoisonCheck.TLSPort,
		time.Duration(cfg.PoisonCheck.TLSTimeout)*time.Second,
	)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	log.StartJanitor(ctx, 48*time.Hour)
	srv, err := server.New(cfg, log, checker)
	if err != nil {
		log.Fatalf("create server failed: %v", err)
	}
	srv.StartCacheJanitor(ctx)
	updater.NewLocalDomainUpdater(cfg, log, srv.ReloadLocalDomains).Start(ctx)
	if err := srv.ListenAndServe(ctx); err != nil {
		log.Fatalf("server stopped: %v", err)
	}
}
