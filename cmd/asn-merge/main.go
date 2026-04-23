package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"lo-dns/internal/asnmerge"
	"lo-dns/internal/config"
	"lo-dns/internal/httpx"
)

func main() {
	configPath := flag.String("config", "config.yaml", "配置文件路径")
	seedPath := flag.String("seed", "", "种子 JSON（人工 asn_file_path），默认从配置读取")
	outPath := flag.String("out", "", "合并输出路径，默认 server.cache_path/domain_asn.merged.json")
	appleRIPE := flag.Bool("apple-ripe", false, "合并 RIPE AS714 到 apple")
	timeout := flag.Duration("timeout", 2*time.Minute, "整次合并总超时")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "加载配置: %v\n", err)
		os.Exit(1)
	}

	seed := *seedPath
	if seed == "" {
		seed = asnmerge.ResolvePath(cfg.BaseDir, cfg.PoisonCheck.ASNFilePath)
	}
	out := *outPath
	if out == "" {
		out = asnmerge.MergedASNPath(cfg.BaseDir, cfg.Server.CachePath)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	downloadNS := httpx.NameserversForDownload(cfg.BootstrapDNS, cfg.Upstream.Local, cfg.Upstream.Overseas)
	downloadHTTP := httpx.NewHTTPClient(downloadNS, *timeout)

	report, err := asnmerge.Merge(ctx, asnmerge.Options{
		SeedPath:       seed,
		OutPath:        out,
		MergeAppleRIPE: *appleRIPE || cfg.PoisonCheck.ASNMergeAppleRIPE,
		HTTPClient:     downloadHTTP,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "合并失败: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("已写入 %s（种子: %s）\n", report.OutPath, report.SeedPath)
	fmt.Printf("更新组织: %v\n", report.OrgsUpdated)
	for k, v := range report.PerSource {
		fmt.Printf("  源 %-22s ok=%v count=%d %s\n", k, v.OK, v.Count, v.Detail)
	}
	for org, n := range report.PrefixesPerOrg {
		fmt.Printf("  org %-12s 前缀数 %d\n", org, n)
	}
}
