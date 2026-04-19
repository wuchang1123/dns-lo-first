package updater

import (
	"context"
	"fmt"
	"sync"
	"time"

	"lo-dns/internal/config"
	"lo-dns/internal/domain"
	"lo-dns/internal/logger"
)

// Updater 定时更新器
type Updater struct {
	domainMgr *domain.Manager
	config    *config.Config
	stopChan  chan struct{}
	stopped   bool
	mu        sync.Mutex
}

// NewUpdater 创建更新器
func NewUpdater(domainMgr *domain.Manager, cfg *config.Config) *Updater {
	return &Updater{
		domainMgr: domainMgr,
		config:    cfg,
		stopChan:  make(chan struct{}),
	}
}

// Start 启动定时更新
func (u *Updater) Start() {
	go u.run()
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

// run 运行更新循环
func (u *Updater) run() {
	u.UpdateAll()

	if u.config.LocalDomains.UpdateInterval > 0 {
		go u.updateLocalDomainsPeriodically()
	}
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

// UpdateAll 立即更新所有数据
func (u *Updater) UpdateAll() error {
	if err := u.updateLocalDomains(); err != nil {
		return fmt.Errorf("更新所在国域名失败: %w", err)
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
