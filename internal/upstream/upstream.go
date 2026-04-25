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

func (c *Client) QueryFirst(ctx context.Context, servers []string, req *dns.Msg) Result {
	if len(servers) == 0 {
		return Result{Err: errors.New("no upstream servers configured")}
	}
	servers = c.usableServers(servers)
	if len(servers) == 0 {
		return Result{Err: errors.New("no usable upstream servers")}
	}
	first := servers[0]
	start := time.Now()
	msg, err := c.Query(ctx, first, req.Copy())
	if err == nil && msg != nil {
		c.recordLatency(first, time.Since(start))
		return Result{Server: first, Msg: msg}
	}
	c.freezeIfTimeout(first, err)
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
				c.recordLatency(server, time.Since(start))
			}
			c.freezeIfTimeout(server, err)
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

func (c *Client) usableServers(servers []string) []string {
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
		until, frozen := c.cooldowns[server]
		if frozen && now.Before(until) {
			if earliestServer == "" || until.Before(earliestUntil) {
				earliestServer = server
				earliestUntil = until
			}
			continue
		}
		if frozen {
			delete(c.cooldowns, server)
		}
		available = append(available, server)
	}
	if len(available) > 0 {
		return c.sortByScore(available)
	}
	if earliestServer != "" {
		delete(c.cooldowns, earliestServer)
		return []string{earliestServer}
	}
	return nil
}

func (c *Client) recordLatency(server string, latency time.Duration) {
	c.scoreMu.Lock()
	defer c.scoreMu.Unlock()
	current, ok := c.latency[server]
	if !ok || current <= 0 {
		c.latency[server] = latency
		return
	}
	c.latency[server] = (current*7 + latency*3) / 10
}

func (c *Client) sortByScore(servers []string) []string {
	groups := map[int64][]string{}
	var scores []int64
	for _, server := range servers {
		score := c.score(server)
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

func (c *Client) score(server string) int64 {
	c.scoreMu.RLock()
	latency := c.latency[server]
	c.scoreMu.RUnlock()
	if latency <= 0 {
		return 0
	}
	return int64(time.Second / latency)
}

func (c *Client) freezeIfTimeout(server string, err error) {
	if err == nil || !isTimeout(err) {
		return
	}
	c.cooldownMu.Lock()
	c.cooldowns[server] = time.Now().Add(c.cooldownTTL)
	c.cooldownMu.Unlock()
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
