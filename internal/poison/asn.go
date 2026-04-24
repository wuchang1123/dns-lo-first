package poison

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"lo-dns/internal/logger"

	"github.com/miekg/dns"
)

// loadASNComposite 后缀始终来自人工文件；各 org 的 IP 前缀优先使用 cache 合并文件，不存在或无效时用人工文件。
func (c *Checker) loadASNComposite(manualPath, mergedPath string) error {
	handData, err := readASNFile(manualPath)
	if err != nil {
		return fmt.Errorf("读取人工 ASN 文件: %w", err)
	}
	var merged *ASNData
	if mergedPath != "" {
		if data, rerr := os.ReadFile(mergedPath); rerr == nil {
			var m ASNData
			if uerr := json.Unmarshal(data, &m); uerr != nil {
				logger.Warnf("解析合并 ASN 缓存失败，前缀回退人工文件: %v", uerr)
			} else if len(m.Orgs) > 0 {
				merged = &m
			}
		} else if !os.IsNotExist(rerr) {
			logger.Warnf("读取合并 ASN 缓存: %v", rerr)
		}
	}
	combined := buildCompositeASN(handData, merged)
	if err := c.replaceASNMaps(combined); err != nil {
		return err
	}
	if merged != nil {
		logger.Infof("加载ASN成功: 后缀来自人工配置, 前缀优先来自合并缓存 (%d 域名映射, %d 组织)", len(c.domainToOrg), len(c.orgToPrefixes))
	} else {
		logger.Infof("加载ASN成功: 仅人工配置（无合并缓存或缓存无效）(%d 域名映射, %d 组织)", len(c.domainToOrg), len(c.orgToPrefixes))
	}
	return nil
}

func readASNFile(path string) (*ASNData, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var asnData ASNData
	if err := json.Unmarshal(data, &asnData); err != nil {
		return nil, err
	}
	return &asnData, nil
}

func buildCompositeASN(hand *ASNData, merged *ASNData) *ASNData {
	out := &ASNData{
		Version:  hand.Version,
		Suffixes: hand.Suffixes,
		Orgs: make(map[string]struct {
			Prefixes []string `json:"prefixes"`
		}),
	}
	for org, ho := range hand.Orgs {
		prefixes := ho.Prefixes
		if merged != nil {
			if mo, ok := merged.Orgs[org]; ok && len(mo.Prefixes) > 0 {
				prefixes = mo.Prefixes
			}
		}
		out.Orgs[org] = struct {
			Prefixes []string `json:"prefixes"`
		}{Prefixes: prefixes}
	}
	return out
}

// replaceASNMaps 用解析后的数据替换内存中的 ASN 映射（持锁）。
func (c *Checker) replaceASNMaps(asnData *ASNData) error {
	if len(asnData.Orgs) == 0 {
		return fmt.Errorf("ASN orgs 为空")
	}
	if len(asnData.Suffixes) == 0 {
		return fmt.Errorf("ASN suffixes 为空")
	}

	domainToOrg := make(map[string]string)
	orgToPrefixes := make(map[string][]net.IPNet)

	for org, orgData := range asnData.Orgs {
		prefixes := make([]net.IPNet, 0, len(orgData.Prefixes))
		for _, prefixStr := range orgData.Prefixes {
			_, ipNet, err := net.ParseCIDR(prefixStr)
			if err != nil {
				logger.Errorf("解析IP段 %s 失败: %v", prefixStr, err)
				continue
			}
			prefixes = append(prefixes, *ipNet)
		}
		orgToPrefixes[org] = prefixes
	}

	for _, suffix := range asnData.Suffixes {
		if suffix.Suffix == "" || suffix.Org == "" {
			continue
		}
		domainToOrg[suffix.Suffix] = suffix.Org
	}

	if len(domainToOrg) == 0 {
		return fmt.Errorf("有效 suffix 映射为空")
	}

	c.asnMu.Lock()
	c.domainToOrg = domainToOrg
	c.orgToPrefixes = orgToPrefixes
	c.asnMu.Unlock()
	return nil
}

// ReloadASN 热重载：重新读取人工文件与 cache 合并文件并合成映射。
func (c *Checker) ReloadASN() error {
	if !c.config.ASNEnabled {
		return nil
	}
	if c.asnManualPath == "" {
		return fmt.Errorf("ASN 人工文件路径未设置")
	}
	return c.loadASNComposite(c.asnManualPath, c.asnMergedPath)
}

func (c *Checker) getOrgByDomain(domain string) string {
	c.asnMu.RLock()
	defer c.asnMu.RUnlock()

	if org, ok := c.domainToOrg[domain]; ok {
		return org
	}

	parts := strings.Split(domain, ".")
	for i := 1; i < len(parts); i++ {
		subDomain := strings.Join(parts[i:], ".")
		if org, ok := c.domainToOrg[subDomain]; ok {
			return org
		}
	}

	return ""
}

func (c *Checker) isIPInOrgPrefixes(ip net.IP, org string) bool {
	c.asnMu.RLock()
	defer c.asnMu.RUnlock()

	prefixes, ok := c.orgToPrefixes[org]
	if !ok {
		return false
	}

	for _, prefix := range prefixes {
		if prefix.Contains(ip) {
			return true
		}
	}

	return false
}

// CheckIPInOrgPrefixes 检查IP是否在域名对应的组织IP段内
func (c *Checker) CheckIPInOrgPrefixes(domain string, ip net.IP) bool {
	if !c.config.ASNEnabled {
		return false
	}

	org := c.getOrgByDomain(domain)
	if org == "" {
		return false
	}

	return c.isIPInOrgPrefixes(ip, org)
}

func (c *Checker) resolveIPToDomain(ip net.IP) string {
	reverseAddr, err := dns.ReverseAddr(ip.String())
	if err != nil {
		return ""
	}

	msg := new(dns.Msg)
	msg.SetQuestion(reverseAddr, dns.TypePTR)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	r, _, err := c.dnsClient.ExchangeContext(ctx, msg, "8.8.8.8:53")
	if err != nil {
		return ""
	}

	if len(r.Answer) > 0 {
		if ptr, ok := r.Answer[0].(*dns.PTR); ok {
			return strings.TrimSuffix(ptr.Ptr, ".")
		}
	}

	return ""
}
