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

type tlsCheckResult struct {
	side    string
	msg     *dns.Msg
	server  string
	ips     []string
	start   time.Time
	elapsed time.Duration
	ok      bool
}

type queryTiming struct {
	local    durationField
	overseas durationField
	tls      durationField
}

type durationField struct {
	value time.Duration
	set   bool
}

const (
	routeBoth route = iota
	routeLocal
	routeOverseas
)

const (
	defaultResolveTimeout      = 8 * time.Second
	optimisticTTL              = 2 * time.Second
	responseCacheMaxAge        = 48 * time.Hour
	responseCacheCleanInterval = 24 * time.Hour
	upstreamGroupLocal         = "local"
	upstreamGroupOverseas      = "overseas"
	upstreamGroupMixed         = "mixed"
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
	client := upstream.New(time.Duration(cfg.PoisonCheck.TLSTimeout) * time.Second)
	client.SetLogger(log)
	if err := client.SetEDNSClientSubnet(cfg.EDNSClientSubnet.Enabled, cfg.EDNSClientSubnet.IPv4, cfg.EDNSClientSubnet.IPv6); err != nil {
		return nil, err
	}
	return &Server{
		cfg:          cfg,
		log:          log,
		client:       client,
		respCache:    respCache,
		verdictCache: verdictCache,
		checker:      checker,
		localOnly:    rules.NewMatcher(cfg.Upstream.LocalOnly),
		overseasOnly: rules.NewMatcher(cfg.Upstream.OverseasOnly),
		localDomains: localDomains,
		keySuspect:   rules.NewMatcher(cfg.KeySuspectDomains()),
	}, nil
}

func (s *Server) StartCacheJanitor(ctx context.Context) {
	s.respCache.StartJanitor(ctx, responseCacheCleanInterval, responseCacheMaxAge, func(removed int) {
		s.log.Infof("cleaned response cache entries removed=%d max_age=%s", removed, responseCacheMaxAge)
	})
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
		s.log.Queryf("%s - - - - []%s", formatQueryTiming(time.Since(start), queryTiming{}), queryStatusSuffix(msg, err))
		return
	}
	q := req.Question[0]
	key := cache.ResponseKey(q)
	if q.Qtype == dns.TypeA {
		if msg, upstreamServer, ok, fresh := s.respCache.Get(key); ok {
			msg.Id = req.Id
			if fresh {
				s.writeAndLog(w, msg, q, start, upstreamServer, queryTiming{})
				return
			}
			poison.SetMinTTL(msg, 2)
			s.writeAndLog(w, msg, q, start, upstreamServer, queryTiming{})
			go s.refresh(req.Copy(), key)
			return
		}
	}

	msg, upstreamServer, timing, err := s.resolve(req.Copy(), q, key)
	if err != nil {
		s.log.Warnf("resolve %s failed: %v", q.Name, err)
		s.writeAndLog(w, errorMsg(req, dns.RcodeServerFailure), q, start, upstreamServer, timing)
		return
	}
	msg.Id = req.Id
	s.writeAndLog(w, msg, q, start, upstreamServer, timing)
	if q.Qtype == dns.TypeA {
		s.respCache.PutWithServer(key, msg, s.cacheTTL(msg), upstreamServer)
	}
}

func (s *Server) writeAndLog(w dns.ResponseWriter, msg *dns.Msg, q dns.Question, start time.Time, upstreamServer string, timing queryTiming) {
	err := w.WriteMsg(msg)
	s.log.Queryf(
		"%s %s  %s  %s  %s  %v%s",
		formatQueryTiming(time.Since(start), timing),
		q.Name,
		dnsTypeString(q.Qtype),
		dnsClassString(q.Qclass),
		formatLogField(upstreamServer),
		poison.StringsForIPs(poison.ExtractIPv4(msg)),
		queryStatusSuffix(msg, err),
	)
}

func (s *Server) refresh(req *dns.Msg, key string) {
	if len(req.Question) == 0 {
		return
	}
	msg, upstreamServer, _, err := s.resolve(req, req.Question[0], key)
	if err != nil {
		s.log.Debugf("background refresh %s failed: %v", req.Question[0].Name, err)
		return
	}
	s.respCache.PutWithServer(key, msg, s.cacheTTL(msg), upstreamServer)
}

func (s *Server) resolve(req *dns.Msg, q dns.Question, key string) (*dns.Msg, string, queryTiming, error) {
	if q.Qtype != dns.TypeA {
		r := s.routeFor(q.Name)
		return s.forward(req, q, groupForRoute(r), s.serversFor(r), r)
	}
	switch s.routeFor(q.Name) {
	case routeLocal:
		return s.forward(req, q, upstreamGroupLocal, s.cfg.Upstream.Servers.Local, routeLocal)
	case routeOverseas:
		return s.forward(req, q, upstreamGroupOverseas, s.cfg.Upstream.Servers.Overseas, routeOverseas)
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

func groupForRoute(r route) string {
	switch r {
	case routeLocal:
		return upstreamGroupLocal
	case routeOverseas:
		return upstreamGroupOverseas
	default:
		return upstreamGroupMixed
	}
}

func (s *Server) forward(req *dns.Msg, q dns.Question, group string, servers []string, routeHint route) (*dns.Msg, string, queryTiming, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultResolveTimeout)
	defer cancel()
	res := s.client.QueryFirst(ctx, group, servers, req)
	timing := timingForRoute(routeHint, res.Elapsed)
	if res.Err != nil {
		return nil, "", timing, res.Err
	}
	if q.Qtype == dns.TypeA {
		qname := rules.Normalize(q.Name)
		if filtered, ok := s.asnAccepted(res.Msg); ok {
			s.log.Debugf("asn accepted %s response for %s", group, qname)
			poison.SetMinTTL(filtered, uint32(optimisticTTL/time.Second))
			return filtered, res.Server, timing, nil
		}
		if s.keySuspect.Match(q.Name) && shouldCheckTLS(res.Msg) {
			tlsResult := s.checkTLSResponseSync(ctx, group, qname, res.Msg.Copy(), res.Server)
			timing.tls = durationField{value: tlsResult.elapsed, set: true}
			s.logTLSCheck(qname, tlsResult)
			if tlsResult.ok {
				s.log.Infof("tls accepted %s response for %s upstream=%s elapsed=%s", group, qname, res.Server, formatDurationMS(tlsResult.elapsed))
				return tlsResult.msg, res.Server, timing, nil
			}
		}
	}
	return res.Msg, res.Server, timing, nil
}

func (s *Server) resolveBoth(req *dns.Msg, q dns.Question, key string) (*dns.Msg, string, queryTiming, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(s.cfg.Server.ConcurrentTimeout)*time.Second)

	ch := make(chan upstreamTaggedResult, 2)
	go func() {
		ch <- upstreamTaggedResult{side: "local", res: s.client.QueryFirst(ctx, upstreamGroupLocal, s.cfg.Upstream.Servers.Local, req.Copy())}
	}()
	go func() {
		ch <- upstreamTaggedResult{side: "overseas", res: s.client.QueryFirst(ctx, upstreamGroupOverseas, s.cfg.Upstream.Servers.Overseas, req.Copy())}
	}()

	var local, overseas *dns.Msg
	var localServer, overseasServer string
	var firstErr error
	timing := queryTiming{}
	qname := rules.Normalize(q.Name)
	processed := 0
	timedOut := false
	tlsCh := make(chan tlsCheckResult, 2)
	tlsPending := 0
	for processed < 2 || tlsPending > 0 {
		select {
		case r := <-ch:
			processed++
			if r.res.Err != nil {
				timing.set(r.side, r.res.Elapsed)
				firstErr = r.res.Err
				continue
			}
			if r.side == "local" {
				local = r.res.Msg
				localServer = r.res.Server
				timing.set(r.side, r.res.Elapsed)
				if filtered, ok := s.asnAccepted(local); ok {
					s.log.Debugf("asn accepted local response for %s", qname)
					poison.SetMinTTL(filtered, uint32(optimisticTTL/time.Second))
					if overseas == nil {
						s.completeBothInBackground(ctx, cancel, ch, qname, local, overseas, filtered, "local", localServer, overseasServer, key, 2-processed)
						return s.finishBoth(qname, local, overseas, filtered, "local", localServer, overseasServer), localServer, timing, nil
					}
					cancel()
					return s.finishBoth(qname, local, overseas, filtered, "local", localServer, overseasServer), localServer, timing, nil
				}
				if s.keySuspect.Match(q.Name) && shouldCheckTLS(local) {
					tlsPending++
					go s.checkTLSResponse(ctx, tlsCh, "local", qname, local.Copy(), localServer)
				}
				continue
			}
			overseas = r.res.Msg
			overseasServer = r.res.Server
			timing.set(r.side, r.res.Elapsed)
			if filtered, ok := s.asnAccepted(overseas); ok {
				s.log.Debugf("asn accepted overseas response for %s", qname)
				poison.SetMinTTL(filtered, uint32(optimisticTTL/time.Second))
				if local == nil {
					s.completeBothInBackground(ctx, cancel, ch, qname, local, overseas, filtered, "overseas", localServer, overseasServer, key, 2-processed)
					return s.finishBoth(qname, local, overseas, filtered, "overseas", localServer, overseasServer), overseasServer, timing, nil
				}
				cancel()
				return s.finishBoth(qname, local, overseas, filtered, "overseas", localServer, overseasServer), overseasServer, timing, nil
			}
			if s.keySuspect.Match(q.Name) && shouldCheckTLS(overseas) {
				tlsPending++
				go s.checkTLSResponse(ctx, tlsCh, "overseas", qname, overseas.Copy(), overseasServer)
			}
		case r := <-tlsCh:
			tlsPending--
			timing.tls = durationField{value: r.elapsed, set: true}
			s.logTLSCheck(qname, r)
			if !r.ok {
				continue
			}
			s.log.Infof("tls accepted %s response for %s upstream=%s elapsed=%s", r.side, qname, r.server, formatDurationMS(r.elapsed))
			if r.side == "local" {
				local = r.msg
				localServer = r.server
			} else {
				overseas = r.msg
				overseasServer = r.server
			}
			cancel()
			return s.finishBoth(qname, local, overseas, r.msg, r.side, localServer, overseasServer), serverForSide(r.side, localServer, overseasServer), timing, nil
		case <-ctx.Done():
			firstErr = ctx.Err()
			processed = 2
			timedOut = true
			tlsPending = 0
		}
	}
	cancel()
	if local != nil && overseas != nil && poison.SimilarIPv4(poison.ExtractIPv4(local), poison.ExtractIPv4(overseas)) {
		return s.finishBoth(qname, local, overseas, overseas, "overseas", localServer, overseasServer), overseasServer, timing, nil
	}
	if overseas != nil {
		if timedOut || local != nil {
			poison.SetMinTTL(overseas, uint32(optimisticTTL/time.Second))
		}
		return s.finishBoth(qname, local, overseas, overseas, "overseas", localServer, overseasServer), overseasServer, timing, nil
	}
	if local != nil {
		poison.SetMinTTL(local, uint32(optimisticTTL/time.Second))
		return s.finishBoth(qname, local, overseas, local, "local", localServer, overseasServer), localServer, timing, nil
	}
	if firstErr == nil {
		firstErr = errors.New("no response from upstream")
	}
	empty := emptyResponse(req)
	poison.SetMinTTL(empty, uint32(optimisticTTL/time.Second))
	return s.finishBoth(qname, local, overseas, empty, "", localServer, overseasServer), "", timing, nil
}

func (s *Server) completeBothInBackground(ctx context.Context, cancel context.CancelFunc, ch <-chan upstreamTaggedResult, qname string, local, overseas, selected *dns.Msg, selectedSide, localServer, overseasServer, key string, remaining int) {
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
					localServer = r.res.Server
				} else {
					overseas = r.res.Msg
					overseasServer = r.res.Server
				}
			case <-ctx.Done():
				remaining = 0
			}
		}
		final := s.finishBoth(qname, local, overseas, selected, selectedSide, localServer, overseasServer)
		finalServer := serverForSide(selectedSide, localServer, overseasServer)
		if local != nil && overseas != nil && poison.SimilarIPv4(poison.ExtractIPv4(local), poison.ExtractIPv4(overseas)) {
			final = overseas
			finalServer = overseasServer
		}
		if final != nil && key != "" {
			s.respCache.PutWithServer(key, final, s.cacheTTL(final), finalServer)
		}
	}()
}

func (s *Server) finishBoth(qname string, local, overseas, selected *dns.Msg, selectedSide, localServer, overseasServer string) *dns.Msg {
	entry := cache.VerdictEntry{
		Result:         "unknown",
		LocalServer:    localServer,
		OverseasServer: overseasServer,
	}
	if local != nil {
		entry.LocalIPs = poison.StringsForIPs(poison.ExtractIPv4(local))
	}
	if overseas != nil {
		entry.OverseasIPs = poison.StringsForIPs(poison.ExtractIPv4(overseas))
	}
	if local != nil && overseas != nil && poison.SimilarIPv4(poison.ExtractIPv4(local), poison.ExtractIPv4(overseas)) {
		entry.Result = "same"
	} else if selectedSide != "" {
		entry.Result = selectedSide
	}
	s.verdictCache.Put(qname, entry, 24*time.Hour)
	return selected
}

func serverForSide(side, localServer, overseasServer string) string {
	switch side {
	case "local":
		return localServer
	case "overseas":
		return overseasServer
	default:
		return ""
	}
}

func (s *Server) checkTLSResponse(ctx context.Context, ch chan<- tlsCheckResult, side, qname string, msg *dns.Msg, server string) {
	ch <- s.checkTLSResponseSync(ctx, side, qname, msg, server)
}

func (s *Server) checkTLSResponseSync(ctx context.Context, side, qname string, msg *dns.Msg, server string) tlsCheckResult {
	start := time.Now()
	ips := poison.ExtractIPv4(msg)
	ok := s.checker.CheckTLS(ctx, qname, ips)
	return tlsCheckResult{
		side:    side,
		msg:     msg,
		server:  server,
		ips:     poison.StringsForIPs(ips),
		start:   start,
		elapsed: time.Since(start),
		ok:      ok,
	}
}

func (s *Server) logTLSCheck(qname string, r tlsCheckResult) {
	status := "FAIL"
	if r.ok {
		status = "OK"
	}
	s.log.Queryf(
		"%s TLS %s %v %s %s %s",
		formatDurationMS(r.elapsed),
		qname,
		r.ips,
		s.log.FormatClock(r.start),
		s.log.FormatClock(r.start.Add(r.elapsed)),
		status,
	)
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

func shouldCheckTLS(msg *dns.Msg) bool {
	return msg != nil && msg.Rcode == dns.RcodeSuccess && len(poison.ExtractIPv4(msg)) > 0
}

func (s *Server) cacheTTL(msg *dns.Msg) time.Duration {
	if msg != nil {
		if len(msg.Answer) == 0 {
			return optimisticTTL
		}
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

func emptyResponse(req *dns.Msg) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetReply(req)
	msg.Rcode = dns.RcodeSuccess
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

func timingForRoute(r route, elapsed time.Duration) queryTiming {
	timing := queryTiming{}
	if elapsed <= 0 {
		return timing
	}
	switch r {
	case routeOverseas:
		timing.overseas = durationField{value: elapsed, set: true}
	default:
		timing.local = durationField{value: elapsed, set: true}
	}
	return timing
}

func (t *queryTiming) set(side string, elapsed time.Duration) {
	if elapsed <= 0 {
		return
	}
	switch side {
	case "local":
		t.local = durationField{value: elapsed, set: true}
	case "overseas":
		t.overseas = durationField{value: elapsed, set: true}
	}
}

func formatQueryTiming(total time.Duration, timing queryTiming) string {
	return fmt.Sprintf(
		"%s(%s+%s+%s)",
		formatDurationMS(total),
		formatDurationPart(timing.local),
		formatDurationPart(timing.overseas),
		formatDurationPart(timing.tls),
	)
}

func formatDurationPart(d durationField) string {
	if !d.set {
		return "-"
	}
	return formatDurationMS(d.value)
}

func formatDurationMS(d time.Duration) string {
	return fmt.Sprintf("%.3fms", float64(d)/float64(time.Millisecond))
}

func formatLogField(value string) string {
	if value == "" {
		return "-"
	}
	return value
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
