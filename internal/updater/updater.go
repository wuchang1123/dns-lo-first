package updater

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"lo-dns/internal/config"
	"lo-dns/internal/domain"
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

	if u.config.MotherlandDomains.UpdateInterval > 0 {
		go u.updateMotherlandDomainsPeriodically()
	}
}

func (u *Updater) updateMotherlandDomainsPeriodically() {
	ticker := time.NewTicker(time.Duration(u.config.MotherlandDomains.UpdateInterval) * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-u.stopChan:
			return
		case <-ticker.C:
			u.updateMotherlandDomains()
		}
	}
}

// UpdateAll 立即更新所有数据
func (u *Updater) UpdateAll() error {
	if err := u.updateMotherlandDomains(); err != nil {
		return fmt.Errorf("更新母国域名失败: %w", err)
	}
	return nil
}

// updateMotherlandDomains 更新母国域名列表
func (u *Updater) updateMotherlandDomains() error {
	if u.config.MotherlandDomains.SourceURL == "" {
		return nil
	}

	log.Println("[UPDATER] 开始更新母国域名列表...")
	start := time.Now()

	if err := u.domainMgr.Update(); err != nil {
		log.Printf("[UPDATER] 更新母国域名列表失败: %v", err)
		return err
	}

	count := u.domainMgr.GetDomainCount()
	log.Printf("[UPDATER] 母国域名列表更新完成，共 %d 个域名，耗时 %v", count, time.Since(start))
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
		"motherland_domains_count": u.domainMgr.GetDomainCount(),
	}
}
