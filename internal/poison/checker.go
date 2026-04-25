package poison

import (
	"context"
	"crypto/tls"
	"net"
	"sort"
	"strconv"
	"time"

	"dns-lo-first/internal/asn"
	"github.com/miekg/dns"
)

type Checker struct {
	db         *asn.DB
	enabled    bool
	asnEnabled bool
	tlsPort    int
	tlsTimeout time.Duration
}

type ASNResult struct {
	Known bool
	Good  []net.IP
}

func New(db *asn.DB, enabled, asnEnabled bool, tlsPort int, tlsTimeout time.Duration) *Checker {
	if tlsPort == 0 {
		tlsPort = 443
	}
	if tlsTimeout <= 0 {
		tlsTimeout = 5 * time.Second
	}
	return &Checker{db: db, enabled: enabled, asnEnabled: asnEnabled, tlsPort: tlsPort, tlsTimeout: tlsTimeout}
}

func (c *Checker) CheckASN(names []string, ips []net.IP) ASNResult {
	if !c.enabled || !c.asnEnabled || c.db == nil {
		return ASNResult{Known: false}
	}
	known, good := c.db.Check(names, ips)
	return ASNResult{Known: known, Good: good}
}

func (c *Checker) CheckTLS(ctx context.Context, serverName string, ips []net.IP) bool {
	if !c.enabled || len(ips) == 0 {
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, c.tlsTimeout)
	defer cancel()

	result := make(chan bool, len(ips))
	launched := 0
	for _, ip := range ips {
		ip := ip
		if ip.To4() == nil {
			continue
		}
		launched++
		go func() {
			dialer := &net.Dialer{Timeout: c.tlsTimeout}
			conn, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(ip.String(), strconv.Itoa(c.tlsPort)), &tls.Config{
				ServerName: serverName,
				MinVersion: tls.VersionTLS12,
			})
			if err != nil {
				result <- false
				return
			}
			_ = conn.Close()
			result <- true
		}()
	}
	for range launched {
		select {
		case ok := <-result:
			if ok {
				return true
			}
		case <-ctx.Done():
			return false
		}
	}
	return false
}

func ExtractIPv4(msg *dns.Msg) []net.IP {
	if msg == nil {
		return nil
	}
	seen := map[string]struct{}{}
	var out []net.IP
	for _, rr := range msg.Answer {
		a, ok := rr.(*dns.A)
		if !ok {
			continue
		}
		ip := a.A.To4()
		if ip == nil {
			continue
		}
		if _, ok := seen[ip.String()]; ok {
			continue
		}
		seen[ip.String()] = struct{}{}
		out = append(out, ip)
	}
	return out
}

func ExtractNames(msg *dns.Msg) []string {
	if msg == nil {
		return nil
	}
	seen := map[string]struct{}{}
	var out []string
	for _, q := range msg.Question {
		if _, ok := seen[q.Name]; !ok {
			seen[q.Name] = struct{}{}
			out = append(out, q.Name)
		}
	}
	for _, rr := range msg.Answer {
		if c, ok := rr.(*dns.CNAME); ok {
			if _, exists := seen[c.Target]; !exists {
				seen[c.Target] = struct{}{}
				out = append(out, c.Target)
			}
		}
	}
	return out
}

func SimilarIPv4(a, b []net.IP) bool {
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	for _, x := range a {
		x4 := x.To4()
		if x4 == nil {
			continue
		}
		for _, y := range b {
			y4 := y.To4()
			if y4 == nil {
				continue
			}
			if x4.Equal(y4) || samePrefix(x4, y4, 24) || samePrefix(x4, y4, 16) {
				return true
			}
		}
	}
	return false
}

func StringsForIPs(ips []net.IP) []string {
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		if ip4 := ip.To4(); ip4 != nil {
			out = append(out, ip4.String())
		}
	}
	sort.Strings(out)
	return out
}

func SetMinTTL(msg *dns.Msg, ttl uint32) {
	if msg == nil {
		return
	}
	for _, rr := range append(append([]dns.RR{}, msg.Answer...), append(msg.Ns, msg.Extra...)...) {
		if rr.Header().Ttl > ttl {
			rr.Header().Ttl = ttl
		}
	}
}

func samePrefix(a, b net.IP, bits int) bool {
	mask := net.CIDRMask(bits, 32)
	return a.Mask(mask).Equal(b.Mask(mask))
}
