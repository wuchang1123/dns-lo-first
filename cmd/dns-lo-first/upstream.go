package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Returned when every upstream answered on the wire but none satisfied
// isAcceptableUpstreamResponse (A query: NOERROR+ usable A, or NXDOMAIN).
var errNoAcceptableUpstreamResponse = errors.New("no upstream returned NOERROR with A records or NXDOMAIN")

type upstreamManager struct {
	cfg               *runtimeConfig
	log               *logger
	bootstrapDNS      []string
	dohBootstrapDNS   []string
	local             []*upstream
	overseas          []*upstream
	inflight          *singleflight
	rand              *rand.Rand
	mu                sync.Mutex
	rep               *reputationStore
	observationEndsAt time.Time // zero => observation disabled (period <= 0)
}

type orderMode int

const (
	orderByScore orderMode = iota
	orderByReputation
)

type upstream struct {
	address      string
	category     string
	isDoH        bool
	url          *url.URL
	score        float64
	frozenUntil  time.Time
	lastLowProbe time.Time
	mu           sync.Mutex
}

func newUpstreamManager(cfg *runtimeConfig, log *logger, bootstrap, dohBootstrap []string, rep *reputationStore) (*upstreamManager, error) {
	m := &upstreamManager{
		cfg:             cfg,
		log:             log,
		bootstrapDNS:    bootstrap,
		dohBootstrapDNS: sanitizeDo53(dohBootstrap),
		inflight:        newSingleflight(),
		rand:            rand.New(rand.NewSource(time.Now().UnixNano())),
		rep:             rep,
	}
	if cfg.observationPeriod > 0 {
		m.observationEndsAt = time.Now().Add(cfg.observationPeriod)
	}
	for _, addr := range cfg.Upstream.Local {
		up, err := newUpstream(addr, categoryLocal, cfg.Upstream.Scoring.InitialScore)
		if err != nil {
			return nil, err
		}
		m.local = append(m.local, up)
	}
	for _, addr := range cfg.Upstream.Overseas {
		up, err := newUpstream(addr, categoryOverseas, cfg.Upstream.Scoring.InitialScore)
		if err != nil {
			return nil, err
		}
		m.overseas = append(m.overseas, up)
	}
	log.Infof("loaded upstreams local=%d overseas=%d doh=%d", len(m.local), len(m.overseas), m.countDoH())
	if !m.observationEndsAt.IsZero() {
		log.Infof("upstream observation period until %s (duration=%s)", m.observationEndsAt.In(log.loc).Format(time.RFC3339), cfg.observationPeriod)
	}
	return m, nil
}

func newUpstream(address, category string, score float64) (*upstream, error) {
	u := &upstream{address: address, category: category, score: score}
	if strings.HasPrefix(address, "https://") {
		parsed, err := url.Parse(address)
		if err != nil {
			return nil, err
		}
		u.isDoH = true
		u.url = parsed
	} else if _, err := normalizeHostPort(address, "53"); err != nil {
		return nil, fmt.Errorf("upstream %s: %w", address, err)
	}
	return u, nil
}

func (m *upstreamManager) countDoH() int {
	n := 0
	for _, u := range append(append([]*upstream{}, m.local...), m.overseas...) {
		if u.isDoH {
			n++
		}
	}
	return n
}

func (m *upstreamManager) Query(ctx context.Context, category string, req *dns.Msg, mode orderMode, source string) (*dns.Msg, string, error) {
	key := fmt.Sprintf("%s|%d|%s", category, mode, makeKey(req.Question[0]))
	v, err := m.inflight.Do(ctx, key, func(ctx context.Context) (any, error) {
		return m.queryCategory(ctx, category, req, mode, source)
	})
	if err != nil {
		return nil, "", err
	}
	res := v.(queryResult)
	return res.msg, res.upstream, nil
}

type queryResult struct {
	msg      *dns.Msg
	upstream string
}

func (m *upstreamManager) queryCategory(ctx context.Context, category string, req *dns.Msg, mode orderMode, source string) (queryResult, error) {
	ordered := m.ordered(category, mode)
	if len(ordered) == 0 {
		return queryResult{}, errors.New("no upstreams configured")
	}

	first := ordered[0]
	msg, err := m.queryOne(ctx, first, req, source)
	if err == nil && isAcceptableUpstreamResponse(req, msg) {
		return queryResult{msg: msg, upstream: first.address}, nil
	}
	if len(ordered) == 1 {
		if err != nil {
			return queryResult{}, err
		}
		return queryResult{}, errNoAcceptableUpstreamResponse
	}

	type one struct {
		msg *dns.Msg
		up  *upstream
		err error
	}
	ch := make(chan one, len(ordered)-1)
	for _, up := range ordered[1:] {
		up := up
		go func() {
			msg, err := m.queryOne(ctx, up, req, source)
			ch <- one{msg: msg, up: up, err: err}
		}()
	}
	var lastErr error
	if err != nil {
		lastErr = err
	} else {
		lastErr = errNoAcceptableUpstreamResponse
	}
	for i := 0; i < len(ordered)-1; i++ {
		select {
		case <-ctx.Done():
			return queryResult{}, ctx.Err()
		case res := <-ch:
			if res.err == nil && isAcceptableUpstreamResponse(req, res.msg) {
				return queryResult{msg: res.msg, upstream: res.up.address}, nil
			}
			if res.err != nil {
				lastErr = res.err
			} else {
				lastErr = errNoAcceptableUpstreamResponse
			}
		}
	}
	return queryResult{}, lastErr
}

func (m *upstreamManager) ordered(category string, mode orderMode) []*upstream {
	var ups []*upstream
	if category == categoryLocal {
		ups = append(ups, m.local...)
	} else {
		ups = append(ups, m.overseas...)
	}
	now := time.Now()
	active := make([]*upstream, 0, len(ups))
	frozen := make([]*upstream, 0)
	for _, up := range ups {
		up.mu.Lock()
		isFrozen := now.Before(up.frozenUntil)
		up.mu.Unlock()
		if isFrozen {
			frozen = append(frozen, up)
		} else {
			active = append(active, up)
		}
	}
	if len(active) == 0 && len(frozen) > 0 {
		sort.Slice(frozen, func(i, j int) bool {
			return frozen[i].frozenUntil.Before(frozen[j].frozenUntil)
		})
		earliest := frozen[0].frozenUntil
		for _, up := range frozen {
			up.mu.Lock()
			if up.frozenUntil.Equal(earliest) {
				up.frozenUntil = time.Time{}
				active = append(active, up)
				up.mu.Unlock()
				continue
			}
			up.mu.Unlock()
			break
		}
	}
	if mode == orderByReputation {
		if m.inObservationPeriod() {
			active = m.orderActiveByScore(active, now)
			if len(active) <= 1 {
				return active
			}
			half := (len(active) + 1) / 2
			candidates := active[:half]
			m.mu.Lock()
			chosen := candidates[m.rand.Intn(len(candidates))]
			m.mu.Unlock()
			return prependChosenFirst(chosen, active)
		}
		// Step 1: sort by reputation desc (tie-break by score desc, then random).
		sort.Slice(active, func(i, j int) bool {
			ai := active[i]
			aj := active[j]
			ri := m.rep.score(ai.address)
			rj := m.rep.score(aj.address)
			if ri != rj {
				return ri > rj
			}
			si := ai.getScore()
			sj := aj.getScore()
			if math.Abs(si-sj) < 0.001 {
				m.mu.Lock()
				less := m.rand.Intn(2) == 0
				m.mu.Unlock()
				return less
			}
			return si > sj
		})

		// Step 2: take top half by reputation, then pick the best score within that half.
		if len(active) <= 1 {
			return active
		}
		half := (len(active) + 1) / 2
		candidates := append([]*upstream(nil), active[:half]...)
		sort.Slice(candidates, func(i, j int) bool {
			si := candidates[i].getScore()
			sj := candidates[j].getScore()
			if math.Abs(si-sj) < 0.001 {
				m.mu.Lock()
				less := m.rand.Intn(2) == 0
				m.mu.Unlock()
				return less
			}
			return si > sj
		})
		chosen := candidates[0]

		return prependChosenFirst(chosen, active)
	}

	return m.orderActiveByScore(active, now)
}

func (m *upstreamManager) inObservationPeriod() bool {
	if m.observationEndsAt.IsZero() {
		return false
	}
	return time.Now().Before(m.observationEndsAt)
}

// orderActiveByScore sorts by score descending (random tie-break), then optionally promotes the lowest-score upstream for probing.
func (m *upstreamManager) orderActiveByScore(active []*upstream, now time.Time) []*upstream {
	sort.Slice(active, func(i, j int) bool {
		si := active[i].getScore()
		sj := active[j].getScore()
		if math.Abs(si-sj) < 0.001 {
			m.mu.Lock()
			less := m.rand.Intn(2) == 0
			m.mu.Unlock()
			return less
		}
		return si > sj
	})
	if len(active) > 1 && m.cfg.lowScoreProbeInterval > 0 {
		low := active[len(active)-1]
		low.mu.Lock()
		shouldProbe := time.Since(low.lastLowProbe) >= m.cfg.lowScoreProbeInterval
		if shouldProbe {
			low.lastLowProbe = now
		}
		low.mu.Unlock()
		if shouldProbe {
			return append([]*upstream{low}, active[:len(active)-1]...)
		}
	}
	return active
}

func prependChosenFirst(chosen *upstream, ordered []*upstream) []*upstream {
	out := make([]*upstream, 0, len(ordered))
	out = append(out, chosen)
	for _, up := range ordered {
		if up == chosen {
			continue
		}
		out = append(out, up)
	}
	return out
}

func (u *upstream) getScore() float64 {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.score
}

func (m *upstreamManager) queryOne(parent context.Context, up *upstream, req *dns.Msg, source string) (*dns.Msg, error) {
	ctx, cancel := context.WithTimeout(parent, m.cfg.upstreamTimeout)
	defer cancel()
	start := time.Now()
	var msg *dns.Msg
	var err error
	if up.isDoH {
		msg, err = m.queryDoH(ctx, up, req)
	} else {
		msg, err = m.queryDo53(ctx, up, req)
	}
	elapsed := time.Since(start)
	if errors.Is(err, context.Canceled) {
		return nil, err
	}
	m.record(up, msg, err, elapsed)
	if err != nil {
		m.log.Queryf("%.3fms UPSTREAM[%s] %s %s %s %s %s %v", float64(elapsed.Microseconds())/1000, source, req.Question[0].Name, up.category, up.address, start.In(m.log.loc).Format("15:04:05.000"), time.Now().In(m.log.loc).Format("15:04:05.000"), err)
		return nil, err
	}
	m.log.Queryf("%.3fms UPSTREAM[%s] %s %s %s %s %s OK ips=%s rcode=%s", float64(elapsed.Microseconds())/1000, source, req.Question[0].Name, up.category, up.address, start.In(m.log.loc).Format("15:04:05.000"), time.Now().In(m.log.loc).Format("15:04:05.000"), strings.Join(extractA(msg), ","), dns.RcodeToString[msg.Rcode])
	return msg, nil
}

func (m *upstreamManager) queryDo53(ctx context.Context, up *upstream, req *dns.Msg) (*dns.Msg, error) {
	addr, err := normalizeHostPort(up.address, "53")
	if err != nil {
		return nil, err
	}
	msg := req.Copy()
	m.applyECS(msg)
	client := &dns.Client{Net: "udp", Timeout: m.cfg.upstreamTimeout}
	resp, _, err := client.ExchangeContext(ctx, msg, addr)
	if err == nil && resp != nil {
		return resp, nil
	}
	client.Net = "tcp"
	resp, _, tcpErr := client.ExchangeContext(ctx, msg, addr)
	if tcpErr != nil {
		if err != nil {
			return nil, err
		}
		return nil, tcpErr
	}
	return resp, nil
}

func (m *upstreamManager) queryDoH(ctx context.Context, up *upstream, req *dns.Msg) (*dns.Msg, error) {
	msg := req.Copy()
	m.applyECS(msg)
	wire, err := msg.Pack()
	if err != nil {
		return nil, err
	}
	resolvers := m.bootstrapDNS
	if up.category == categoryOverseas {
		resolvers = m.dohBootstrapDNS
	}
	if len(resolvers) == 0 {
		resolvers = m.bootstrapDNS
	}
	transport := &http.Transport{
		Proxy:       http.ProxyFromEnvironment,
		DialContext: dohDialer(up.url.Hostname(), resolvers),
		TLSClientConfig: &tls.Config{
			ServerName: up.url.Hostname(),
			MinVersion: tls.VersionTLS12,
		},
	}
	client := &http.Client{Transport: transport, Timeout: m.cfg.upstreamTimeout}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, up.url.String(), bytes.NewReader(wire))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Accept", "application/dns-message")
	httpReq.Header.Set("Content-Type", "application/dns-message")
	httpResp, err := client.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer httpResp.Body.Close()
	if httpResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("doh status %s", httpResp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(httpResp.Body, 65536))
	if err != nil {
		return nil, err
	}
	resp := new(dns.Msg)
	if err := resp.Unpack(body); err != nil {
		return nil, err
	}
	return resp, nil
}

func (m *upstreamManager) applyECS(msg *dns.Msg) {
	if !m.cfg.Upstream.ECS.Enabled || m.cfg.Upstream.ECS.IPv4 == "" {
		return
	}
	ip := net.ParseIP(m.cfg.Upstream.ECS.IPv4).To4()
	if ip == nil {
		return
	}
	opt := msg.IsEdns0()
	if opt == nil {
		opt = &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
		msg.Extra = append(msg.Extra, opt)
	}
	filtered := opt.Option[:0]
	for _, option := range opt.Option {
		if option.Option() != dns.EDNS0SUBNET {
			filtered = append(filtered, option)
		}
	}
	opt.Option = filtered
	opt.Option = append(opt.Option, &dns.EDNS0_SUBNET{
		Code:          dns.EDNS0SUBNET,
		Family:        1,
		SourceNetmask: m.cfg.Upstream.ECS.SourcePrefix,
		SourceScope:   m.cfg.Upstream.ECS.ScopePrefix,
		Address:       ip,
	})
}

func (m *upstreamManager) record(up *upstream, msg *dns.Msg, err error, elapsed time.Duration) {
	up.mu.Lock()
	defer up.mu.Unlock()
	cfg := m.cfg.Upstream.Scoring
	if err != nil {
		penalty := cfg.FailurePenalty
		if errors.Is(err, context.DeadlineExceeded) || os.IsTimeout(err) {
			penalty = cfg.TimeoutPenalty
			up.frozenUntil = time.Now().Add(m.cfg.freezeDuration)
		}
		up.score = clamp(up.score-penalty, cfg.MinScore, cfg.MaxScore)
		return
	}
	if msg != nil && (msg.Rcode == dns.RcodeServerFailure || msg.Rcode == dns.RcodeRefused || msg.Rcode == dns.RcodeFormatError) {
		up.score = clamp(up.score-cfg.FailurePenalty, cfg.MinScore, cfg.MaxScore)
		return
	}
	latencyPenalty := float64(elapsed.Milliseconds()/100) * cfg.LatencyPenaltyPer100ms
	if up.category == categoryOverseas {
		latencyPenalty *= cfg.OverseasLatencyDiscount
	}
	up.score = clamp(up.score+cfg.SuccessReward-latencyPenalty, cfg.MinScore, cfg.MaxScore)
}

func clamp(v, min, max float64) float64 {
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}

const dohDialMaxIPs = 8

func dohDialer(host string, resolvers []string) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		_, port, err := net.SplitHostPort(addr)
		if err != nil {
			port = "443"
		}
		ips, err := resolveHostDo53(ctx, host, resolvers)
		if err != nil {
			return nil, err
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("no address for %s", host)
		}
		if len(ips) > dohDialMaxIPs {
			ips = ips[:dohDialMaxIPs]
		}
		dialer := &net.Dialer{}
		var lastErr error
		for _, ip := range ips {
			conn, derr := dialer.DialContext(ctx, network, net.JoinHostPort(ip, port))
			if derr == nil {
				return conn, nil
			}
			lastErr = derr
		}
		if lastErr != nil {
			return nil, lastErr
		}
		return nil, fmt.Errorf("dial %s: all IPs failed", host)
	}
}

func resolveHostDo53(ctx context.Context, host string, resolvers []string) ([]string, error) {
	if net.ParseIP(host) != nil {
		return []string{host}, nil
	}
	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(host), dns.TypeA)
	client := &dns.Client{Net: "udp", Timeout: 3 * time.Second}
	var lastErr error
	for _, resolver := range resolvers {
		addr, err := normalizeHostPort(resolver, "53")
		if err != nil {
			continue
		}
		resp, _, err := client.ExchangeContext(ctx, req, addr)
		if err != nil {
			lastErr = err
			continue
		}
		ips := extractA(resp)
		if len(ips) > 0 {
			return ips, nil
		}
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("resolve %s failed", host)
}

func downloadWithBootstrap(rawURL string, resolvers []string) ([]byte, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{
		Proxy:       http.ProxyFromEnvironment,
		DialContext: dohDialer(parsed.Hostname(), resolvers),
		TLSClientConfig: &tls.Config{
			ServerName: parsed.Hostname(),
			MinVersion: tls.VersionTLS12,
		},
	}
	client := &http.Client{Transport: transport, Timeout: 20 * time.Second}
	resp, err := client.Get(rawURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("status %s", resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 8<<20))
}
