package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
)

func makeKey(q dns.Question) string {
	return strings.ToLower(dns.Fqdn(q.Name)) + "|" + fmt.Sprint(q.Qtype) + "|" + fmt.Sprint(q.Qclass)
}

func questionInfo(msg *dns.Msg) (string, uint16, uint16) {
	if len(msg.Question) == 0 {
		return ".", 0, 0
	}
	q := msg.Question[0]
	return q.Name, q.Qtype, q.Qclass
}

func servfail(req *dns.Msg) *dns.Msg {
	resp := new(dns.Msg)
	resp.SetRcode(req, dns.RcodeServerFailure)
	return resp
}

func cacheableBasic(msg *dns.Msg) bool {
	if msg == nil {
		return false
	}
	if msg.Rcode == dns.RcodeNameError {
		return true
	}
	if msg.Rcode != dns.RcodeSuccess {
		return false
	}
	return hasA(msg)
}

func hasA(msg *dns.Msg) bool {
	return len(extractA(msg)) > 0
}

func extractA(msg *dns.Msg) []string {
	if msg == nil {
		return nil
	}
	seen := make(map[string]struct{})
	var ips []string
	for _, rr := range msg.Answer {
		if a, ok := rr.(*dns.A); ok {
			ip := a.A.String()
			if _, exists := seen[ip]; !exists {
				seen[ip] = struct{}{}
				ips = append(ips, ip)
			}
		}
	}
	sort.Strings(ips)
	return ips
}

func setAllTTL(msg *dns.Msg, ttl uint32) {
	for _, rr := range msg.Answer {
		rr.Header().Ttl = ttl
	}
	for _, rr := range msg.Ns {
		rr.Header().Ttl = ttl
	}
	for _, rr := range msg.Extra {
		if rr.Header().Rrtype != dns.TypeOPT {
			rr.Header().Ttl = ttl
		}
	}
}

func rrStrings(rrs []dns.RR) []string {
	out := make([]string, 0, len(rrs))
	for _, rr := range rrs {
		if rr.Header().Rrtype == dns.TypeOPT {
			continue
		}
		out = append(out, rr.String())
	}
	return out
}

func ipSetsConsistent(a, b []string) bool {
	for _, left := range a {
		la, err := netip.ParseAddr(left)
		if err != nil || !la.Is4() {
			continue
		}
		for _, right := range b {
			ra, err := netip.ParseAddr(right)
			if err != nil || !ra.Is4() {
				continue
			}
			if la == ra || samePrefix(la, ra, 24) || samePrefix(la, ra, 16) {
				return true
			}
		}
	}
	return false
}

func samePrefix(a, b netip.Addr, bits int) bool {
	pa, err := a.Prefix(bits)
	if err != nil {
		return false
	}
	pb, err := b.Prefix(bits)
	if err != nil {
		return false
	}
	return pa.Masked() == pb.Masked()
}

func normalizeHostPort(addr, defaultPort string) (string, error) {
	if strings.HasPrefix(addr, "https://") {
		return "", fmt.Errorf("not a Do53 address")
	}
	host, port, err := net.SplitHostPort(addr)
	if err == nil {
		return net.JoinHostPort(host, port), nil
	}
	if strings.Contains(err.Error(), "missing port in address") {
		return net.JoinHostPort(addr, defaultPort), nil
	}
	return "", err
}

func sanitizeDo53(addrs []string) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, addr := range addrs {
		if strings.HasPrefix(addr, "https://") {
			continue
		}
		normalized, err := normalizeHostPort(addr, "53")
		if err != nil {
			continue
		}
		host, _, err := net.SplitHostPort(normalized)
		if err != nil {
			continue
		}
		ip := net.ParseIP(host)
		if ip != nil && ip.IsLoopback() {
			continue
		}
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		out = append(out, normalized)
	}
	return out
}

func writeJSON(path string, v any, log *logger) {
	path = filepath.Clean(path)
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		log.Warnf("create cache directory failed path=%s err=%v", path, err)
		return
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		log.Warnf("marshal cache failed path=%s err=%v", path, err)
		return
	}

	tmpFile, err := os.CreateTemp(dir, filepath.Base(path)+".*.tmp")
	if err != nil {
		log.Warnf("create temp cache file failed dir=%s err=%v", dir, err)
		return
	}
	tmpPath := tmpFile.Name()
	success := false
	defer func() {
		if !success {
			_ = os.Remove(tmpPath)
		}
	}()

	if _, err := tmpFile.Write(b); err != nil {
		_ = tmpFile.Close()
		log.Warnf("write cache failed path=%s err=%v", tmpPath, err)
		return
	}
	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		log.Warnf("sync cache failed path=%s err=%v", tmpPath, err)
		return
	}
	if err := tmpFile.Close(); err != nil {
		log.Warnf("close cache tmp failed path=%s err=%v", tmpPath, err)
		return
	}

	if err := os.Rename(tmpPath, path); err != nil {
		// Destination parent may have disappeared between CreateTemp and Rename (race / external rm).
		if err2 := os.MkdirAll(dir, 0o755); err2 == nil {
			if err3 := os.Rename(tmpPath, path); err3 == nil {
				success = true
				return
			}
		}
		if err4 := os.WriteFile(path, b, 0o644); err4 != nil {
			log.Warnf("replace cache failed path=%s err=%v (fallback=%v)", path, err, err4)
			return
		}
		_ = os.Remove(tmpPath)
		success = true
		return
	}
	success = true
}

func cleanupLogs(dir string, maxAgeHours int, log *logger) {
	if maxAgeHours <= 0 {
		return
	}
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for range ticker.C {
		cutoff := time.Now().Add(-time.Duration(maxAgeHours) * time.Hour)
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			path := filepath.Join(dir, entry.Name())
			info, err := entry.Info()
			if err == nil && info.ModTime().Before(cutoff) {
				if err := os.Remove(path); err != nil {
					log.Warnf("remove old log failed path=%s err=%v", path, err)
				}
			}
		}
	}
}
