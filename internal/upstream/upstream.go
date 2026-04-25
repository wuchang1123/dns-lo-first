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
	"strings"
	"time"

	"github.com/miekg/dns"
)

type Client struct {
	timeout time.Duration
	http    *http.Client
	dns     *dns.Client
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
		timeout: timeout,
		http:    &http.Client{Timeout: timeout},
		dns:     &dns.Client{Net: "udp", Timeout: timeout},
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
	servers = shuffled(servers)
	first := servers[0]
	msg, err := c.Query(ctx, first, req.Copy())
	if err == nil && msg != nil {
		return Result{Server: first, Msg: msg}
	}
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
			msg, err := c.Query(ctx, server, req.Copy())
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
