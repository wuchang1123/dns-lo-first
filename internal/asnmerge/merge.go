// Package asnmerge 从多个公开数据源合并 IPv4/IPv6 前缀，写入 cache 下合并文件；
// 域名后缀映射（suffixes）始终复制自种子（asn_file_path），不从网络推断。
package asnmerge

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const userAgent = "lo-first-asnmerge/1.0 (+https://github.com/)"

// MergedFileName 多源 ASN 合并产物固定文件名（位于 server.cache_path 目录）。
const MergedFileName = "domain_asn.merged.json"

// File 与 data/domain_asn.json 同结构；Generated 为可选审计字段。
type File struct {
	Version   int                       `json:"version"`
	Orgs      map[string]orgData        `json:"orgs"`
	Suffixes  []suffixEntry             `json:"suffixes"`
	Generated string                    `json:"generated,omitempty"`
	Sources   map[string]sourceMeta     `json:"sources,omitempty"`
}

type orgData struct {
	Prefixes []string `json:"prefixes"`
}

type suffixEntry struct {
	Suffix string `json:"suffix"`
	Org    string `json:"org"`
}

type sourceMeta struct {
	OK     bool   `json:"ok"`
	Count  int    `json:"count,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// Report 一次合并的摘要。
type Report struct {
	OutPath        string
	SeedPath       string
	PerSource      map[string]sourceMeta
	OrgsUpdated    []string
	PrefixesPerOrg map[string]int
}

// Options 合并参数。
type Options struct {
	SeedPath       string
	OutPath        string
	MergeAppleRIPE bool
	HTTPClient     *http.Client
}

// Merge 读取种子 JSON（人工 asn_file_path），拉取各源前缀，与种子中已有前缀取并集、去重后写入 OutPath（一般为 cache 下合并文件）。
func Merge(ctx context.Context, opts Options) (*Report, error) {
	if opts.OutPath == "" {
		return nil, fmt.Errorf("asnmerge: OutPath 为空")
	}
	if opts.SeedPath == "" {
		opts.SeedPath = opts.OutPath
	}
	client := opts.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 90 * time.Second}
	}

	seedBytes, err := os.ReadFile(opts.SeedPath)
	if err != nil {
		return nil, fmt.Errorf("读取种子 %s: %w", opts.SeedPath, err)
	}

	var doc File
	if err := json.Unmarshal(seedBytes, &doc); err != nil {
		return nil, fmt.Errorf("解析种子 JSON: %w", err)
	}
	if doc.Orgs == nil {
		doc.Orgs = make(map[string]orgData)
	}
	if len(doc.Suffixes) == 0 {
		return nil, fmt.Errorf("种子 suffixes 为空，拒绝覆盖（请保留手工域名映射）")
	}

	report := &Report{
		OutPath:        opts.OutPath,
		SeedPath:       opts.SeedPath,
		PerSource:      make(map[string]sourceMeta),
		PrefixesPerOrg: make(map[string]int),
	}

	type fetch struct {
		org    string
		name   string
		do     func(context.Context, *http.Client) ([]string, error)
		enabled bool
	}
	fetches := []fetch{
		{"google", "gstatic_goog_json", fetchGooglePrefixes, true},
		{"cloudflare", "cloudflare_ips", fetchCloudflarePrefixes, true},
		{"microsoft", "ripe_as8075", func(c context.Context, cl *http.Client) ([]string, error) {
			return fetchRIPEAnnounced(c, cl, "8075")
		}, true},
	}
	if opts.MergeAppleRIPE {
		fetches = append(fetches, fetch{"apple", "ripe_as714", func(c context.Context, cl *http.Client) ([]string, error) {
			return fetchRIPEAnnounced(c, cl, "714")
		}, true})
	}

	for _, f := range fetches {
		if !f.enabled {
			continue
		}
		if _, hasOrg := doc.Orgs[f.org]; !hasOrg {
			continue
		}
		prefixes, err := f.do(ctx, client)
		if err != nil && f.org == "microsoft" {
			if p2, e2 := fetchBGPViewASNPrefixes(ctx, client, "8075"); e2 == nil && len(p2) > 0 {
				prefixes = p2
				err = nil
				report.PerSource["bgpview_as8075_fallback"] = sourceMeta{OK: true, Count: len(p2), Detail: "used when ripe_as8075 failed"}
			}
		}
		if err != nil {
			report.PerSource[f.name] = sourceMeta{OK: false, Detail: err.Error()}
			continue
		}
		report.PerSource[f.name] = sourceMeta{OK: true, Count: len(prefixes)}
		merged := unionPrefixes(doc.Orgs[f.org].Prefixes, prefixes)
		od := doc.Orgs[f.org]
		od.Prefixes = merged
		doc.Orgs[f.org] = od
		report.OrgsUpdated = append(report.OrgsUpdated, f.org)
	}

	doc.Version++
	doc.Generated = time.Now().UTC().Format(time.RFC3339)
	doc.Sources = report.PerSource

	for org, od := range doc.Orgs {
		report.PrefixesPerOrg[org] = len(od.Prefixes)
	}

	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, err
	}
	out = append(out, '\n')

	tmp := opts.OutPath + ".tmp"
	if err := os.WriteFile(tmp, out, 0644); err != nil {
		return nil, fmt.Errorf("写入临时文件: %w", err)
	}
	if err := os.Rename(tmp, opts.OutPath); err != nil {
		_ = os.Remove(tmp)
		return nil, fmt.Errorf("替换目标文件: %w", err)
	}

	return report, nil
}

func unionPrefixes(seed []string, fetched []string) []string {
	seen := make(map[string]struct{})
	add := func(p string) {
		p = strings.TrimSpace(p)
		if p == "" || !isIPv4CIDR(p) {
			return
		}
		seen[p] = struct{}{}
	}
	for _, p := range seed {
		add(p)
	}
	for _, p := range fetched {
		add(p)
	}
	out := make([]string, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// isIPv4CIDR 仅接受 IPv4 CIDR（合并产物不含 IPv6，与当前判毒仅查 A 记录一致）。
func isIPv4CIDR(s string) bool {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		return false
	}
	return n.IP.To4() != nil
}

func fetchGooglePrefixes(ctx context.Context, client *http.Client) ([]string, error) {
	const u = "https://www.gstatic.com/ipranges/goog.json"
	body, err := httpGet(ctx, client, u)
	if err != nil {
		return nil, err
	}
	var wrap struct {
		Prefixes []struct {
			IPv4 string `json:"ipv4Prefix"`
			IPv6 string `json:"ipv6Prefix"`
		} `json:"prefixes"`
	}
	if err := json.Unmarshal(body, &wrap); err != nil {
		return nil, err
	}
	var out []string
	for _, p := range wrap.Prefixes {
		if p.IPv4 != "" {
			out = append(out, p.IPv4)
		}
	}
	return out, nil
}

func fetchCloudflarePrefixes(ctx context.Context, client *http.Client) ([]string, error) {
	var all []string
	for _, u := range []string{
		"https://www.cloudflare.com/ips-v4",
	} {
		body, err := httpGet(ctx, client, u)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", u, err)
		}
		sc := bufio.NewScanner(bytes.NewReader(body))
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			all = append(all, line)
		}
		if err := sc.Err(); err != nil {
			return nil, err
		}
	}
	return all, nil
}

func fetchRIPEAnnounced(ctx context.Context, client *http.Client, asn string) ([]string, error) {
	asn = strings.TrimPrefix(strings.ToUpper(asn), "AS")
	u := fmt.Sprintf("https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS%s", asn)
	body, err := httpGet(ctx, client, u)
	if err != nil {
		return nil, err
	}
	var wrap struct {
		Status  string `json:"status"`
		Data    struct {
			Prefixes []struct {
				Prefix string `json:"prefix"`
			} `json:"prefixes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &wrap); err != nil {
		return nil, err
	}
	if wrap.Status != "ok" {
		return nil, fmt.Errorf("ripe stat status=%q", wrap.Status)
	}
	out := make([]string, 0, len(wrap.Data.Prefixes))
	for _, p := range wrap.Data.Prefixes {
		if p.Prefix != "" {
			out = append(out, p.Prefix)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("ripe stat 无前缀")
	}
	return out, nil
}

func fetchBGPViewASNPrefixes(ctx context.Context, client *http.Client, asn string) ([]string, error) {
	asn = strings.TrimPrefix(strings.ToUpper(asn), "AS")
	u := fmt.Sprintf("https://api.bgpview.io/asn/%s/prefixes", asn)
	body, err := httpGet(ctx, client, u)
	if err != nil {
		return nil, err
	}
	var wrap struct {
		Status string `json:"status"`
		Data   struct {
			IPv4 []struct {
				Prefix string `json:"prefix"`
			} `json:"ipv4_prefixes"`
			IPv6 []struct {
				Prefix string `json:"prefix"`
			} `json:"ipv6_prefixes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &wrap); err != nil {
		return nil, err
	}
	if wrap.Status != "ok" {
		return nil, fmt.Errorf("bgpview status=%q", wrap.Status)
	}
	var out []string
	for _, p := range wrap.Data.IPv4 {
		if p.Prefix != "" {
			out = append(out, p.Prefix)
		}
	}
	for _, p := range wrap.Data.IPv6 {
		if p.Prefix != "" {
			out = append(out, p.Prefix)
		}
	}
	return out, nil
}

func httpGet(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/json, text/plain, */*")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		slurp, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(slurp)))
	}
	return io.ReadAll(io.LimitReader(resp.Body, 32<<20))
}

// ResolvePath 相对于 baseDir 解析路径。
func ResolvePath(baseDir, p string) string {
	if filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(baseDir, p)
}

// MergedASNPath 合并产物绝对路径：baseDir + serverCachePath + MergedFileName。
func MergedASNPath(baseDir, serverCachePath string) string {
	cd := serverCachePath
	if !filepath.IsAbs(cd) {
		cd = filepath.Join(baseDir, cd)
	}
	return filepath.Join(cd, MergedFileName)
}
