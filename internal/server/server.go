package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"dns-lo-first/internal/cache"
	"dns-lo-first/internal/config"
	"dns-lo-first/internal/logger"
	"dns-lo-first/internal/poison"
	"dns-lo-first/internal/rules"
	"dns-lo-first/internal/upstream"
	"github.com/miekg/dns"
)

type Server struct {
	cfg            *config.Config
	log            *logger.Logger
	client         *upstream.Client
	respCache      *cache.ResponseCache
	verdictCache   *cache.VerdictCache
	checker        *poison.Checker
	localOnly      *rules.Matcher
	overseasOnly   *rules.Matcher
	localDomainsMu sync.RWMutex
	localDomains   *rules.Matcher
	keySuspect     *rules.Matcher
}

type route int

type upstreamTaggedResult struct {
	side string
	res  upstream.Result
}

const (
	routeBoth route = iota
	routeLocal
	routeOverseas
)

const (
	defaultResolveTimeout = 8 * time.Second
	optimisticTTL         = 2 * time.Second
)

func New(cfg *config.Config, log *logger.Logger, checker *poison.Checker) (*Server, error) {
	respCache, err := cache.NewResponseCache(cfg.Server.CachePath, cfg.Server.CacheSize)
	if err != nil {
		return nil, err
	}
	verdictCache, err := cache.NewVerdictCache(cfg.Server.CachePath)
	if err != nil {
		return nil, err
	}
	localDomains, err := loadLocalDomains(cfg.LocalDomains.FilePath)
	if err != nil {
		return nil, err
	}
	return &Server{
		cfg:          cfg,
		log:          log,
		client:       upstream.New(time.Duration(cfg.PoisonCheck.TLSTimeout) * time.Second),
		respCache:    respCache,
		verdictCache: verdictCache,
		checker:      checker,
		localOnly:    rules.NewMatcher(cfg.Upstream.LocalOnly),
		overseasOnly: rules.NewMatcher(cfg.Upstream.OverseasOnly),
		localDomains: localDomains,
		keySuspect:   rules.NewMatcher(cfg.KeySuspectDomains()),
	}, nil
}

func (s *Server) ReloadLocalDomains() error {
	matcher, err := loadLocalDomains(s.cfg.LocalDomains.FilePath)
	if err != nil {
		return err
	}
	s.localDomainsMu.Lock()
	s.localDomains = matcher
	s.localDomainsMu.Unlock()
	s.log.Infof("reloaded local domains: %s", s.cfg.LocalDomains.FilePath)
	return nil
}

func loadLocalDomains(path string) (*rules.Matcher, error) {
	domains, err := rules.LoadDomainFile(path)
	if err != nil {
		return nil, err
	}
	return rules.NewMatcher(domains), nil
}

func (s *Server) ListenAndServe(ctx context.Context) error {
	dns.HandleFunc(".", s.ServeDNS)
	udp := &dns.Server{Addr: s.cfg.Server.Listen, Net: "udp"}
	tcp := &dns.Server{Addr: s.cfg.Server.Listen, Net: "tcp"}
	errCh := make(chan error, 2)
	go func() { errCh <- udp.ListenAndServe() }()
	go func() { errCh <- tcp.ListenAndServe() }()
	s.log.Infof("dns server listening on %s (udp/tcp)", s.cfg.Server.Listen)
	select {
	case err := <-errCh:
		_ = udp.Shutdown()
		_ = tcp.Shutdown()
		return err
	case <-ctx.Done():
		s.log.Infof("shutdown signal received, stopping dns server")
		_ = udp.Shutdown()
		_ = tcp.Shutdown()
		return nil
	}
}

func (s *Server) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	start := time.Now()
	if len(req.Question) == 0 {
		msg := errorMsg(req, dns.RcodeFormatError)
		err := w.WriteMsg(msg)
		s.log.Queryf("%s - - - []%s", formatDurationMS(time.Since(start)), queryStatusSuffix(msg, err))
		return
	}
	q := req.Question[0]
	key := cache.ResponseKey(q)
	if q.Qtype == dns.TypeA {
		if msg, ok, fresh := s.respCache.Get(key); ok {
			msg.Id = req.Id
			if fresh {
				s.writeAndLog(w, msg, q, start)
				return
			}
			poison.SetMinTTL(msg, 2)
			s.writeAndLog(w, msg, q, start)
			go s.refresh(req.Copy(), key)
			return
		}
	}

	msg, err := s.resolve(req.Copy(), q, key)
	if err != nil {
		s.log.Warnf("resolve %s failed: %v", q.Name, err)
		s.writeAndLog(w, errorMsg(req, dns.RcodeServerFailure), q, start)
		return
	}
	msg.Id = req.Id
	s.writeAndLog(w, msg, q, start)
	if q.Qtype == dns.TypeA {
		s.respCache.Put(key, msg, s.cacheTTL(msg))
	}
}

func (s *Server) writeAndLog(w dns.ResponseWriter, msg *dns.Msg, q dns.Question, start time.Time) {
	err := w.WriteMsg(msg)
	s.log.Queryf(
		"%s %s  %s  %s  %v%s",
		formatDurationMS(time.Since(start)),
		q.Name,
		dnsTypeString(q.Qtype),
		dnsClassString(q.Qclass),
		poison.StringsForIPs(poison.ExtractIPv4(msg)),
		queryStatusSuffix(msg, err),
	)
}

func (s *Server) refresh(req *dns.Msg, key string) {
	if len(req.Question) == 0 {
		return
	}
	msg, err := s.resolve(req, req.Question[0], key)
	if err != nil {
		s.log.Debugf("background refresh %s failed: %v", req.Question[0].Name, err)
		return
	}
	s.respCache.Put(key, msg, s.cacheTTL(msg))
}

func (s *Server) resolve(req *dns.Msg, q dns.Question, key string) (*dns.Msg, error) {
	if q.Qtype != dns.TypeA {
		return s.forward(req, s.serversFor(s.routeFor(q.Name)))
	}
	switch s.routeFor(q.Name) {
	case routeLocal:
		return s.forward(req, s.cfg.Upstream.Servers.Local)
	case routeOverseas:
		return s.forward(req, s.cfg.Upstream.Servers.Overseas)
	default:
		return s.resolveBoth(req, q, key)
	}
}

func (s *Server) routeFor(name string) route {
	if s.overseasOnly.Match(name) {
		return routeOverseas
	}
	s.localDomainsMu.RLock()
	isLocalDomain := s.localDomains.Match(name)
	s.localDomainsMu.RUnlock()
	if s.localOnly.Match(name) || isLocalDomain {
		return routeLocal
	}
	return routeBoth
}

func (s *Server) serversFor(r route) []string {
	switch r {
	case routeLocal:
		return s.cfg.Upstream.Servers.Local
	case routeOverseas:
		return s.cfg.Upstream.Servers.Overseas
	default:
		return append(append([]string{}, s.cfg.Upstream.Servers.Local...), s.cfg.Upstream.Servers.Overseas...)
	}
}

func (s *Server) forward(req *dns.Msg, servers []string) (*dns.Msg, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultResolveTimeout)
	defer cancel()
	r := s.client.QueryFirst(ctx, servers, req)
	if r.Err != nil {
		return nil, r.Err
	}
	return r.Msg, nil
}

func (s *Server) resolveBoth(req *dns.Msg, q dns.Question, key string) (*dns.Msg, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(s.cfg.Server.ConcurrentTimeout)*time.Second)

	ch := make(chan upstreamTaggedResult, 2)
	go func() {
		ch <- upstreamTaggedResult{side: "local", res: s.client.QueryFirst(ctx, s.cfg.Upstream.Servers.Local, req.Copy())}
	}()
	go func() {
		ch <- upstreamTaggedResult{side: "overseas", res: s.client.QueryFirst(ctx, s.cfg.Upstream.Servers.Overseas, req.Copy())}
	}()

	var local, overseas *dns.Msg
	var firstErr error
	qname := rules.Normalize(q.Name)
	processed := 0
	for processed < 2 {
		select {
		case r := <-ch:
			processed++
			if r.res.Err != nil {
				firstErr = r.res.Err
				continue
			}
			if r.side == "local" {
				local = r.res.Msg
				if s.keySuspect.Match(q.Name) && s.checker.CheckTLS(ctx, qname, poison.ExtractIPv4(local)) {
					s.log.Infof("tls accepted local response for %s", qname)
					if overseas == nil {
						s.completeBothInBackground(ctx, cancel, ch, qname, local, overseas, local, key, 2-processed)
						return s.finishBoth(qname, local, overseas, local), nil
					}
					cancel()
					return s.finishBoth(qname, local, overseas, local), nil
				}
				continue
			}
			overseas = r.res.Msg
			if filtered, ok := s.asnAccepted(overseas); ok {
				s.log.Debugf("asn accepted overseas response for %s", qname)
				poison.SetMinTTL(filtered, uint32(optimisticTTL/time.Second))
				if local == nil {
					s.completeBothInBackground(ctx, cancel, ch, qname, local, overseas, filtered, key, 2-processed)
					return s.finishBoth(qname, local, overseas, filtered), nil
				}
				cancel()
				return s.finishBoth(qname, local, overseas, filtered), nil
			}
		case <-ctx.Done():
			firstErr = ctx.Err()
			processed = 2
		}
	}
	cancel()
	if local != nil && overseas != nil && poison.SimilarIPv4(poison.ExtractIPv4(local), poison.ExtractIPv4(overseas)) {
		return s.finishBoth(qname, local, overseas, local), nil
	}
	if overseas != nil {
		return s.finishBoth(qname, local, overseas, overseas), nil
	}
	if local != nil {
		poison.SetMinTTL(local, uint32(optimisticTTL/time.Second))
		return s.finishBoth(qname, local, overseas, local), nil
	}
	if firstErr == nil {
		firstErr = errors.New("no response from upstream")
	}
	return nil, firstErr
}

func (s *Server) completeBothInBackground(ctx context.Context, cancel context.CancelFunc, ch <-chan upstreamTaggedResult, qname string, local, overseas, selected *dns.Msg, key string, remaining int) {
	go func() {
		defer cancel()
		for remaining > 0 {
			select {
			case r := <-ch:
				remaining--
				if r.res.Err != nil || r.res.Msg == nil {
					continue
				}
				if r.side == "local" {
					local = r.res.Msg
				} else {
					overseas = r.res.Msg
				}
			case <-ctx.Done():
				remaining = 0
			}
		}
		final := s.finishBoth(qname, local, overseas, selected)
		if local != nil && overseas != nil && poison.SimilarIPv4(poison.ExtractIPv4(local), poison.ExtractIPv4(overseas)) {
			final = local
		}
		if final != nil && key != "" {
			s.respCache.Put(key, final, s.cacheTTL(final))
		}
	}()
}

func (s *Server) finishBoth(qname string, local, overseas, selected *dns.Msg) *dns.Msg {
	entry := cache.VerdictEntry{Result: "unknown"}
	if local != nil {
		entry.LocalIPs = poison.StringsForIPs(poison.ExtractIPv4(local))
	}
	if overseas != nil {
		entry.OverseasIPs = poison.StringsForIPs(poison.ExtractIPv4(overseas))
	}
	if local != nil && overseas != nil && poison.SimilarIPv4(poison.ExtractIPv4(local), poison.ExtractIPv4(overseas)) {
		entry.Result = "same"
	} else if selected == local {
		entry.Result = "local"
	} else if selected == overseas {
		entry.Result = "overseas"
	}
	s.verdictCache.Put(qname, entry, 24*time.Hour)
	return selected
}

func (s *Server) asnAccepted(msg *dns.Msg) (*dns.Msg, bool) {
	ips := poison.ExtractIPv4(msg)
	if len(ips) == 0 {
		return nil, false
	}
	result := s.checker.CheckASN(poison.ExtractNames(msg), ips)
	if result.Known && len(result.Good) > 0 {
		return FilterA(msg, result.Good), true
	}
	return nil, false
}

func (s *Server) cacheTTL(msg *dns.Msg) time.Duration {
	if msg != nil {
		for _, rr := range msg.Answer {
			if rr.Header().Ttl <= uint32(optimisticTTL/time.Second) {
				return optimisticTTL
			}
		}
	}
	return time.Duration(s.cfg.Server.DomainTTL) * time.Second
}

func errorMsg(req *dns.Msg, rcode int) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetRcode(req, rcode)
	return msg
}

func dnsTypeString(qtype uint16) string {
	if s, ok := dns.TypeToString[qtype]; ok {
		return s
	}
	return dns.Type(qtype).String()
}

func dnsClassString(qclass uint16) string {
	if s, ok := dns.ClassToString[qclass]; ok {
		return s
	}
	return dns.Class(qclass).String()
}

func formatDurationMS(d time.Duration) string {
	return fmt.Sprintf("%.3fms", float64(d)/float64(time.Millisecond))
}

func queryStatusSuffix(msg *dns.Msg, writeErr error) string {
	suffix := ""
	if msg != nil && msg.Rcode != dns.RcodeSuccess {
		suffix += " " + dns.RcodeToString[msg.Rcode]
	}
	if writeErr != nil {
		suffix += fmt.Sprintf(" %v", writeErr)
	}
	return suffix
}

func FilterA(msg *dns.Msg, allowed []net.IP) *dns.Msg {
	if len(allowed) == 0 || msg == nil {
		return msg
	}
	allowedSet := map[string]struct{}{}
	for _, ip := range allowed {
		if ip4 := ip.To4(); ip4 != nil {
			allowedSet[ip4.String()] = struct{}{}
		}
	}
	cp := msg.Copy()
	var answer []dns.RR
	for _, rr := range cp.Answer {
		a, ok := rr.(*dns.A)
		if !ok {
			answer = append(answer, rr)
			continue
		}
		if _, ok := allowedSet[a.A.To4().String()]; ok {
			answer = append(answer, rr)
		}
	}
	cp.Answer = answer
	return cp
}
