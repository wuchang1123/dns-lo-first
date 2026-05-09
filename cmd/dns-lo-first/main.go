package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	configPath := flag.String("config", "config.yaml", "path to config file")
	flag.Parse()

	cfg, err := loadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load config: %v\n", err)
		os.Exit(1)
	}

	log, err := newLogger(cfg.Log.Dir, cfg.Log.QueryFile, cfg.Log.Level, cfg.location)
	if err != nil {
		fmt.Fprintf(os.Stderr, "init logger: %v\n", err)
		os.Exit(1)
	}
	defer log.Close()

	log.Infof("starting dns-lo-first listen=%s config=%s", cfg.Server.Listen, *configPath)
	server, err := newDNSServer(cfg, log)
	if err != nil {
		log.Fatalf("init server: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := server.Start(ctx); err != nil {
		log.Fatalf("server stopped with error: %v", err)
	}
	log.Infof("server stopped")
}
