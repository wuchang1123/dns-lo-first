package poison

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"lo-dns/internal/asnmerge"
	"lo-dns/internal/config"
	"lo-dns/internal/logger"
	"lo-dns/internal/upstream"

	"github.com/miekg/dns"
)

// NewChecker 创建检查器
func NewChecker(cfg config.PoisonCheckConfig, upstreamMgr *upstream.Manager, baseDir string, cachePath string) *Checker {
	cacheDir := cachePath
	if !filepath.IsAbs(cacheDir) {
		cacheDir = filepath.Join(baseDir, cacheDir)
	}
	os.MkdirAll(cacheDir, 0755)

	checker := &Checker{
		config:        cfg,
		sem:           make(chan struct{}, cfg.ConcurrentChecks),
		cache:         make(cacheData),
		cacheTTL:      time.Duration(cfg.CacheTTL) * time.Minute,
		cacheFile:     filepath.Join(cacheDir, "tls_cache.json"),
		upstreamMgr:   upstreamMgr,
		stopChan:      make(chan struct{}),
		domainToOrg:   make(map[string]string),
		orgToPrefixes: make(map[string][]net.IPNet),
		dnsClient: &dns.Client{
			Timeout: 5 * time.Second,
		},
	}

	checker.loadCache()

	asnManual := cfg.ASNFilePath
	if !filepath.IsAbs(asnManual) {
		asnManual = filepath.Join(baseDir, asnManual)
	}
	checker.asnManualPath = asnManual
	checker.asnMergedPath = filepath.Join(cacheDir, asnmerge.MergedFileName)
	if cfg.ASNEnabled {
		if err := checker.loadASNComposite(asnManual, checker.asnMergedPath); err != nil {
			logger.Errorf("加载 ASN 失败: %v", err)
		}
	}

	skipE := make(map[string]struct{})
	skipW := make(map[string]struct{})
	for _, s := range cfg.SkipTLSVerifyDomains {
		appendDomainPatternLine(s, skipE, skipW)
	}
	if strings.TrimSpace(cfg.SkipTLSVerifyDomainsPath) != "" {
		skipPath := config.ResolveDataPath(baseDir, cfg.SkipTLSVerifyDomainsPath)
		e2, w2, err := loadDomainPatternFile(skipPath)
		if err != nil {
			logger.Warnf("读取 skip_tls_verify 域名列表失败: %v", err)
		} else {
			mergeDomainPatternMaps(skipE, skipW, e2, w2)
		}
	}
	checker.tlsSkipVerifySet = skipE
	checker.tlsSkipVerifyWildcardOnly = skipW
	if len(skipE)+len(skipW) > 0 {
		logger.Infof("TLS 判毒排除列表（跳过证书校验）: %d apex/子树，%d *. 严格子域", len(skipE), len(skipW))
	}

	checkE := make(map[string]struct{})
	checkW := make(map[string]struct{})
	for _, s := range cfg.Checklist {
		appendDomainPatternLine(s, checkE, checkW)
	}
	if strings.TrimSpace(cfg.ChecklistPath) != "" {
		listPath := config.ResolveDataPath(baseDir, cfg.ChecklistPath)
		e2, w2, err := loadDomainPatternFile(listPath)
		if err != nil {
			logger.Warnf("读取 checklist 失败，将对所有域名判毒: %v", err)
		} else {
			mergeDomainPatternMaps(checkE, checkW, e2, w2)
		}
	}
	checker.checklistSet = checkE
	checker.checklistWildcardOnly = checkW
	checker.checklistEnabled = len(checkE)+len(checkW) > 0
	if checker.checklistEnabled {
		logger.Infof("判毒白名单（checklist）生效: 仅对 %d apex/子树，%d *. 严格子域 做判毒", len(checkE), len(checkW))
	}

	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			checker.checkAndSyncCacheFile()
			checker.saveCache()
		}
	}()

	if cfg.CacheRefreshInterval > 0 {
		go checker.runCacheRefresh()
	}

	return checker
}

// Stop 停止后台任务（缓存刷新等）
func (c *Checker) Stop() {
	close(c.stopChan)
}
