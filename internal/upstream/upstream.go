package upstream

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type Client struct {
	timeout     time.Duration
	http        *http.Client
	dns         *dns.Client
	cooldownMu  sync.Mutex
	cooldowns   map[string]time.Time
	cooldownTTL time.Duration
	scoreMu     sync.RWMutex
	latency     map[string]time.Duration
	log         Logger
}

type Logger interface {
	Debugf(format string, args ...any)
	Infof(format string, args ...any)
	Warnf(format string, args ...any)
}

type Result struct {
	Server string
	Msg    *dns.Msg
	Err    error
}

func New(timeout time.Duration) *Client {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &Client{
		timeout:     timeout,
		http:        &http.Client{Timeout: timeout},
		dns:         &dns.Client{Net: "udp", Timeout: timeout},
		cooldowns:   map[string]time.Time{},
		cooldownTTL: time.Minute,
		latency:     map[string]time.Duration{},
	}
}

func (c *Client) SetLogger(log Logger) {
	c.log = log
}

func (c *Client) Query(ctx context.Context, server string, req *dns.Msg) (*dns.Msg, error) {
	server = strings.TrimSpace(server)
	if server == "" {
		return nil, errors.New("empty upstream server")
	}
	if strings.HasPrefix(server, "https://") || strings.HasPrefix(server, "http://") {
		return c.queryDoH(ctx, server, req)
	}
	return c.queryDo53(ctx, server, req)
}

func (c *Client) QueryFirst(ctx context.Context, group string, servers []string, req *dns.Msg) Result {
	if len(servers) == 0 {
		return Result{Err: errors.New("no upstream servers configured")}
	}
	servers = c.usableServers(group, servers)
	if len(servers) == 0 {
		return Result{Err: errors.New("no usable upstream servers")}
	}
	first := servers[0]
	start := time.Now()
	msg, err := c.Query(ctx, first, req.Copy())
	if err == nil && msg != nil {
		c.recordLatency(group, first, time.Since(start))
		return Result{Server: first, Msg: msg}
	}
	c.freezeIfTimeout(group, first, err)
	if len(servers) == 1 {
		return Result{Server: first, Err: err}
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	rest := servers[1:]
	ch := make(chan Result, len(rest))
	for _, s := range rest {
		server := s
		go func() {
			start := time.Now()
			msg, err := c.Query(ctx, server, req.Copy())
			if err == nil && msg != nil {
				c.recordLatency(group, server, time.Since(start))
			}
			c.freezeIfTimeout(group, server, err)
			ch <- Result{Server: server, Msg: msg, Err: err}
		}()
	}
	last := Result{Server: first, Err: err}
	for range rest {
		r := <-ch
		if r.Err == nil && r.Msg != nil {
			cancel()
			return r
		}
		last = r
	}
	return last
}

func (c *Client) usableServers(group string, servers []string) []string {
	now := time.Now()
	c.cooldownMu.Lock()
	defer c.cooldownMu.Unlock()

	var available []string
	var earliestServer string
	var earliestUntil time.Time
	for _, server := range servers {
		server = strings.TrimSpace(server)
		if server == "" {
			continue
		}
		key := scopedKey(group, server)
		until, frozen := c.cooldowns[key]
		if frozen && now.Before(until) {
			if earliestServer == "" || until.Before(earliestUntil) {
				earliestServer = server
				earliestUntil = until
			}
			continue
		}
		if frozen {
			delete(c.cooldowns, key)
			c.logInfof("upstream thawed group=%s server=%s reason=expired", normalizeGroup(group), server)
		}
		available = append(available, server)
	}
	if len(available) > 0 {
		return c.sortByScore(group, available)
	}
	if earliestServer != "" {
		delete(c.cooldowns, scopedKey(group, earliestServer))
		c.logInfof("upstream thawed group=%s server=%s reason=all_frozen earliest_until=%s", normalizeGroup(group), earliestServer, earliestUntil.Format(time.RFC3339))
		return []string{earliestServer}
	}
	return nil
}

func (c *Client) recordLatency(group, server string, latency time.Duration) {
	key := scopedKey(group, server)
	c.scoreMu.Lock()
	current, ok := c.latency[key]
	oldScore := scoreForLatency(current)
	var next time.Duration
	if !ok || current <= 0 {
		next = latency
	} else {
		next = (current*7 + latency*3) / 10
	}
	c.latency[key] = next
	newScore := scoreForLatency(next)
	c.scoreMu.Unlock()

	if oldScore != newScore || current != next {
		c.logDebugf(
			"upstream score updated group=%s server=%s latency=%s avg_latency=%s score=%d old_score=%d",
			normalizeGroup(group),
			server,
			latency,
			next,
			newScore,
			oldScore,
		)
	}
}

func (c *Client) sortByScore(group string, servers []string) []string {
	groups := map[int64][]string{}
	var scores []int64
	for _, server := range servers {
		score := c.score(group, server)
		if _, ok := groups[score]; !ok {
			scores = append(scores, score)
		}
		groups[score] = append(groups[score], server)
	}
	sort.Slice(scores, func(i, j int) bool {
		return scores[i] > scores[j]
	})
	var out []string
	for _, score := range scores {
		out = append(out, shuffled(groups[score])...)
	}
	return out
}

func (c *Client) score(group, server string) int64 {
	c.scoreMu.RLock()
	latency := c.latency[scopedKey(group, server)]
	c.scoreMu.RUnlock()
	if latency <= 0 {
		return 0
	}
	return scoreForLatency(latency)
}

func (c *Client) freezeIfTimeout(group, server string, err error) {
	if err == nil || !isTimeout(err) {
		return
	}
	until := time.Now().Add(c.cooldownTTL)
	c.cooldownMu.Lock()
	c.cooldowns[scopedKey(group, server)] = until
	c.cooldownMu.Unlock()
	c.logWarnf("upstream frozen group=%s server=%s duration=%s until=%s reason=%v", normalizeGroup(group), server, c.cooldownTTL, until.Format(time.RFC3339), err)
}

func scoreForLatency(latency time.Duration) int64 {
	if latency <= 0 {
		return 0
	}
	return int64(time.Second / latency)
}

func scopedKey(group, server string) string {
	return normalizeGroup(group) + "|" + strings.TrimSpace(server)
}

func normalizeGroup(group string) string {
	group = strings.TrimSpace(group)
	if group == "" {
		return "default"
	}
	return group
}

func (c *Client) logDebugf(format string, args ...any) {
	if c.log != nil {
		c.log.Debugf(format, args...)
	}
}

func (c *Client) logInfof(format string, args ...any) {
	if c.log != nil {
		c.log.Infof(format, args...)
	}
}

func (c *Client) logWarnf(format string, args ...any) {
	if c.log != nil {
		c.log.Warnf(format, args...)
	}
}

func isTimeout(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func shuffled(in []string) []string {
	out := append([]string{}, in...)
	rand.Shuffle(len(out), func(i, j int) {
		out[i], out[j] = out[j], out[i]
	})
	return out
}

func (c *Client) queryDo53(ctx context.Context, server string, req *dns.Msg) (*dns.Msg, error) {
	if _, _, err := net.SplitHostPort(server); err != nil {
		server = net.JoinHostPort(server, "53")
	}
	done := make(chan Result, 1)
	go func() {
		msg, _, err := c.dns.Exchange(req, server)
		done <- Result{Msg: msg, Err: err}
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case r := <-done:
		return r.Msg, r.Err
	}
}

func (c *Client) queryDoH(ctx context.Context, server string, req *dns.Msg) (*dns.Msg, error) {
	packed, err := req.Pack()
	if err != nil {
		return nil, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, server, bytes.NewReader(packed))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("content-type", "application/dns-message")
	httpReq.Header.Set("accept", "application/dns-message")

	resp, err := c.http.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("doh status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, err
	}
	var msg dns.Msg
	if err := msg.Unpack(body); err != nil {
		return nil, err
	}
	return &msg, nil
}
