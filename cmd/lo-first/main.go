package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"lo-dns/internal/config"
	"lo-dns/internal/domain"
	"lo-dns/internal/poison"
	"lo-dns/internal/server"
	"lo-dns/internal/updater"
	"lo-dns/internal/upstream"
)

// 自定义日志写入器，使用配置的时区
type timezoneLogWriter struct {
	mu       sync.Mutex
	file     *os.File
	timezone *time.Location
}

func (w *timezoneLogWriter) Write(p []byte) (n int, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	now := time.Now().In(w.timezone)
	logLine := fmt.Sprintf("%s %s", now.Format("2006/01/02 15:04:05"), string(p))
	return w.file.WriteString(logLine)
}

var (
	configPath = flag.String("config", "config.yaml", "配置文件路径")
	updateOnly = flag.Bool("update-only", false, "仅更新数据，不启动服务器")
	version    = flag.Bool("version", false, "显示版本信息")
)

const (
	AppName    = "LO-DNS"
	AppVersion = "1.0.0"
)

func main() {
	flag.Parse()

	if *version {
		fmt.Printf("%s v%s\n", AppName, AppVersion)
		return
	}

	// 加载配置
	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("加载配置失败: %v", err)
	}

	// 创建目录
	cacheDir := filepath.Join(cfg.BaseDir, "cache")
	dataDir := filepath.Join(cfg.BaseDir, "data")
	logDir := filepath.Join(cfg.BaseDir, "log")

	if err := os.MkdirAll(cfg.BaseDir, 0755); err != nil {
		log.Fatalf("创建基础目录失败: %v", err)
	}
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		log.Fatalf("创建缓存目录失败: %v", err)
	}
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		log.Fatalf("创建数据目录失败: %v", err)
	}
	if err := os.MkdirAll(logDir, 0755); err != nil {
		log.Fatalf("创建日志目录失败: %v", err)
	}

	// 设置日志输出到文件（按日期每天一个文件）
	var currentDateStr string
	var logMutex sync.Mutex
	var tzLoc *time.Location
	var logWriter *timezoneLogWriter

	rotateLogFile := func() error {
		loc, err := time.LoadLocation(cfg.Server.LogTimezone)
		if err != nil {
			log.Printf("[WARN] 无法加载时区 %s: %v，尝试使用 Local 时区", cfg.Server.LogTimezone, err)
			loc = time.Local
			if loc == nil || loc.String() == "UTC" {
				log.Printf("[WARN] Local 时区为 UTC 或不可用，尝试常见时区")
				for _, tz := range []string{"Asia/Shanghai", "Asia/Tokyo", "America/New_York", "Europe/London"} {
					if tz == cfg.Server.LogTimezone {
						continue
					}
					if loc, err := time.LoadLocation(tz); err == nil && loc.String() != "UTC" {
						log.Printf("[INFO] 使用备用时区: %s (%s)", tz, loc)
						goto locFound
					}
				}
				loc = time.UTC
				log.Printf("[WARN] 使用 UTC 时区")
			}
		}
	locFound:
		tzLoc = loc
		now := time.Now().In(loc)
		dateStr := now.Format("2006-01-02")
		if dateStr == currentDateStr && logWriter != nil {
			return nil
		}
		logFilePath := filepath.Join(logDir, fmt.Sprintf("lo-first-%s.log", dateStr))
		f, err := os.OpenFile(logFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return err
		}
		if logWriter != nil {
			logWriter.mu.Lock()
			if logWriter.file != nil {
				logWriter.file.Close()
			}
			logWriter.file = f
			logWriter.timezone = tzLoc
			logWriter.mu.Unlock()
		} else {
			logWriter = &timezoneLogWriter{
				file:     f,
				timezone: tzLoc,
			}
			log.SetFlags(0)
			log.SetOutput(logWriter)
		}
		currentDateStr = dateStr
		log.Printf("[LOG ROTATE] 日志文件轮转到: %s", dateStr)
		return nil
	}

	if err := rotateLogFile(); err != nil {
		log.Fatalf("打开日志文件失败: %v", err)
	}

	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			logMutex.Lock()
			rotateLogFile()
			logMutex.Unlock()
		}
	}()

	log.Printf("[%s] 启动中...", AppName)
	log.Printf("配置文件: %s", *configPath)
	log.Printf("基础目录: %s", cfg.BaseDir)

	// 创建上游DNS管理器
	upstreamMgr := upstream.NewManager(cfg.Upstream.Local, cfg.Upstream.Overseas)

	// 创建域名管理器
	domainMgr := domain.NewManager(domain.Config{
		SourceURL:      cfg.LocalDomains.SourceURL,
		FilePath:       filepath.Join(cfg.BaseDir, cfg.LocalDomains.FilePath),
		UpdateInterval: cfg.LocalDomains.UpdateInterval,
		Custom:         cfg.LocalDomains.Custom,
		Overpass:       cfg.LocalDomains.Overpass,
	})
	if err := domainMgr.Load(); err != nil {
		log.Printf("加载所在国域名列表失败: %v", err)
	}

	// 创建判毒检查器
	poisonChecker := poison.NewChecker(cfg.PoisonCheck, upstreamMgr, cfg.BaseDir)

	// 创建DNS服务器
	dnsServer := server.NewServer(cfg, upstreamMgr, domainMgr, poisonChecker)

	// 创建更新器
	updater := updater.NewUpdater(domainMgr, cfg)

	// 如果仅更新数据
	if *updateOnly {
		log.Println("仅更新数据模式")
		if err := updater.UpdateAll(); err != nil {
			log.Fatalf("更新数据失败: %v", err)
		}
		log.Println("数据更新完成")
		return
	}

	// 启动定时更新
	updater.Start()
	defer updater.Stop()

	// 设置信号处理
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// 启动DNS服务器
	if err := dnsServer.Start(); err != nil {
		log.Fatalf("启动DNS服务器失败: %v", err)
	}

	log.Printf("[%s] 服务器已启动，监听 %s", AppName, cfg.Server.Listen)
	log.Println("按 Ctrl+C 停止服务器")

	// 等待信号
	<-sigChan
	log.Println("正在关闭...")

	updater.Stop()

	log.Printf("[%s] 已关闭", AppName)
}
