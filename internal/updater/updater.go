package updater

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"lo-dns/internal/config"
	"lo-dns/internal/domain"
	"lo-dns/internal/iprange"
)

// Updater 定时更新器
type Updater struct {
	domainMgr  *domain.Manager
	ipRangeMgr *iprange.Manager
	config     *config.Config
	stopChan   chan struct{}
	stopped    bool
	mu         sync.Mutex
}

// NewUpdater 创建更新器
func NewUpdater(domainMgr *domain.Manager, ipRangeMgr *iprange.Manager, cfg *config.Config) *Updater {
	return &Updater{
		domainMgr:  domainMgr,
		ipRangeMgr: ipRangeMgr,
		config:     cfg,
		stopChan:   make(chan struct{}),
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

	if u.config.ChinaDomains.UpdateInterval > 0 {
		go u.updateChinaDomainsPeriodically()
	}

	for name, source := range u.config.OverseasIPRanges.Sources {
		if source.UpdateInterval > 0 {
			go u.updateIPRangePeriodically(name, source.UpdateInterval)
		}
	}
}

func (u *Updater) updateChinaDomainsPeriodically() {
	ticker := time.NewTicker(time.Duration(u.config.ChinaDomains.UpdateInterval) * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-u.stopChan:
			return
		case <-ticker.C:
			u.updateChinaDomains()
		}
	}
}

func (u *Updater) updateIPRangePeriodically(name string, interval int) {
	ticker := time.NewTicker(time.Duration(interval) * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-u.stopChan:
			return
		case <-ticker.C:
			u.updateIPRange(name)
		}
	}
}

// UpdateAll 立即更新所有数据
func (u *Updater) UpdateAll() error {
	var errs []error

	if err := u.updateChinaDomains(); err != nil {
		errs = append(errs, fmt.Errorf("更新中国域名失败: %w", err))
	}

	for name := range u.config.OverseasIPRanges.Sources {
		if err := u.updateIPRange(name); err != nil {
			errs = append(errs, fmt.Errorf("更新 %s IP段失败: %w", name, err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("更新过程中发生 %d 个错误", len(errs))
	}
	return nil
}

// updateChinaDomains 更新中国域名列表
func (u *Updater) updateChinaDomains() error {
	if u.config.ChinaDomains.SourceURL == "" {
		return nil
	}

	log.Println("[UPDATER] 开始更新中国域名列表...")
	start := time.Now()

	if err := u.domainMgr.Update(); err != nil {
		log.Printf("[UPDATER] 更新中国域名列表失败: %v", err)
		return err
	}

	count := u.domainMgr.GetDomainCount()
	log.Printf("[UPDATER] 中国域名列表更新完成，共 %d 个域名，耗时 %v", count, time.Since(start))
	return nil
}

// updateIPRange 更新指定服务的IP段
func (u *Updater) updateIPRange(name string) error {
	source, ok := u.config.OverseasIPRanges.Sources[name]
	if !ok || source.URL == "" {
		return nil
	}

	log.Printf("[UPDATER] 开始更新 %s IP段...", name)
	start := time.Now()

	if err := u.ipRangeMgr.Update(); err != nil {
		log.Printf("[UPDATER] 更新 %s IP段失败: %v", name, err)
		return err
	}

	log.Printf("[UPDATER] %s IP段更新完成，耗时 %v", name, time.Since(start))
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
		"china_domains_count": u.domainMgr.GetDomainCount(),
		"ip_range_services":   u.ipRangeMgr.GetAllServices(),
	}
}
