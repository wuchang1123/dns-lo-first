package updater

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"lo-dns/internal/asnmerge"
	"lo-dns/internal/config"
	"lo-dns/internal/domain"
	"lo-dns/internal/logger"
	"lo-dns/internal/poison"
)

// Updater 定时更新器
type Updater struct {
	domainMgr     *domain.Manager
	poisonChecker *poison.Checker
	config        *config.Config
	stopChan      chan struct{}
	stopped       bool
	mu            sync.Mutex
}

// NewUpdater 创建更新器；poisonChecker 可为 nil（仅写文件、不重载）。
func NewUpdater(domainMgr *domain.Manager, poisonChecker *poison.Checker, cfg *config.Config) *Updater {
	return &Updater{
		domainMgr:     domainMgr,
		poisonChecker: poisonChecker,
		config:        cfg,
		stopChan:      make(chan struct{}),
	}
}

// Start 先同步执行一次全量更新（合并缓存缺失时才会跑 ASN 多源合并），再启动定时节流；须在监听 DNS 之前调用。
func (u *Updater) Start() {
	if err := u.UpdateAll(); err != nil {
		logger.Warnf("[UPDATER] 启动时全量更新: %v", err)
	}
	if u.config.LocalDomains.UpdateInterval > 0 {
		go u.updateLocalDomainsPeriodically()
	}
	if u.config.PoisonCheck.ASNMergeIntervalHours > 0 {
		go u.updateASNMergePeriodically()
	}
}

// Stop 停止更新
func (u *Updater) Stop() {
	u.mu.Lock()
	defer u.mu.Unlock()

	if u.stopped {
		return
	}

	close(u.stopChan)
	u.stopped = true
}

func (u *Updater) updateLocalDomainsPeriodically() {
	ticker := time.NewTicker(time.Duration(u.config.LocalDomains.UpdateInterval) * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-u.stopChan:
			return
		case <-ticker.C:
			u.updateLocalDomains()
		}
	}
}

func (u *Updater) updateASNMergePeriodically() {
	ticker := time.NewTicker(time.Duration(u.config.PoisonCheck.ASNMergeIntervalHours) * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-u.stopChan:
			return
		case <-ticker.C:
			if err := u.updateASNMerge(); err != nil {
				logger.Printf("[UPDATER] 定时 ASN 合并失败: %v", err)
			}
		}
	}
}

// UpdateAll 立即更新所有数据。ASN 多源合并仅在 cache 下 domain_asn.merged.json 不存在时执行（已有文件则跳过，避免每次启动拉网）。
func (u *Updater) UpdateAll() error {
	if u.config.PoisonCheck.ASNEnabled {
		mergedPath := asnmerge.MergedASNPath(u.config.BaseDir, u.config.Server.CachePath)
		if _, err := os.Stat(mergedPath); os.IsNotExist(err) {
			logger.Infof("[UPDATER] 未找到合并缓存，开始 ASN 多源合并 → %s", mergedPath)
			if err := u.updateASNMerge(); err != nil {
				logger.Warnf("[UPDATER] ASN 多源合并失败，沿用人工 asn 前缀: %v", err)
			} else {
				logger.Infof("[UPDATER] ASN 多源合并已完成")
			}
		} else if err != nil {
			logger.Warnf("[UPDATER] 无法访问合并缓存 %s: %v，跳过启动时合并", mergedPath, err)
		} else {
			logger.Infof("[UPDATER] 合并缓存已存在，跳过启动时 ASN 合并: %s", mergedPath)
		}
	}
	localErr := u.updateLocalDomains()
	if localErr != nil {
		return fmt.Errorf("更新所在国域名失败: %w", localErr)
	}
	return nil
}

// updateLocalDomains 更新所在国域名列表
func (u *Updater) updateLocalDomains() error {
	if u.config.LocalDomains.SourceURL == "" {
		return nil
	}

	logger.Println("[UPDATER] 开始更新所在国域名列表...")
	start := time.Now()

	if err := u.domainMgr.Update(); err != nil {
		logger.Printf("[UPDATER] 更新所在国域名列表失败: %v", err)
		return err
	}

	count := u.domainMgr.GetDomainCount()
	logger.Printf("[UPDATER] 所在国域名列表更新完成，共 %d 个域名，耗时 %v", count, time.Since(start))
	return nil
}

func (u *Updater) updateASNMerge() error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	seed := asnmerge.ResolvePath(u.config.BaseDir, u.config.PoisonCheck.ASNFilePath)
	out := asnmerge.MergedASNPath(u.config.BaseDir, u.config.Server.CachePath)

	report, err := asnmerge.Merge(ctx, asnmerge.Options{
		SeedPath:       seed,
		OutPath:        out,
		MergeAppleRIPE: u.config.PoisonCheck.ASNMergeAppleRIPE,
	})
	if err != nil {
		return err
	}
	for name, meta := range report.PerSource {
		if !meta.OK {
			logger.Warnf("[UPDATER] ASN 源 %s 失败: %s", name, meta.Detail)
			continue
		}
		logger.Printf("[UPDATER] ASN 源 %s 前缀数 %d %s", name, meta.Count, meta.Detail)
	}
	if u.poisonChecker != nil {
		if err := u.poisonChecker.ReloadASN(); err != nil {
			logger.Warnf("[UPDATER] ASN 热重载失败: %v", err)
		}
	}
	logger.Printf("[UPDATER] ASN 合并已写入 %s，更新组织: %v", out, report.OrgsUpdated)
	return nil
}

// ForceUpdate 强制立即更新
func (u *Updater) ForceUpdate(ctx context.Context) error {
	done := make(chan error, 1)

	go func() {
		done <- u.UpdateAll()
	}()

	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// GetStatus 获取更新器状态
func (u *Updater) GetStatus() map[string]interface{} {
	return map[string]interface{}{
		"local_domains_count": u.domainMgr.GetDomainCount(),
	}
}
