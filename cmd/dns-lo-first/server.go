package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type dnsServer struct {
	cfg           *runtimeConfig
	log           *logger
	upstreams     *upstreamManager
	responseCache *responseCache
	resultCache   *resultCache
	localOnly     *matcher
	localDomains  *matcher
	domainMu      sync.RWMutex
}

func newDNSServer(cfg *runtimeConfig, log *logger) (*dnsServer, error) {
	localOnly := newMatcher(cfg.Routing.LocalOnly)
	localDomains := newMatcher(nil)
	localFileMissing := false
	if cfg.Routing.LocalDomain.FilePath != "" {
		items, err := loadDomainFile(cfg.Routing.LocalDomain.FilePath)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				localFileMissing = true
				log.Warnf("local_domains file missing path=%s; immediate download will be attempted", cfg.Routing.LocalDomain.FilePath)
			} else {
				log.Warnf("load local_domains failed path=%s err=%v", cfg.Routing.LocalDomain.FilePath, err)
			}
		}
		localDomains = newMatcher(items)
		log.Infof("loaded local_domains count=%d missing=%t", len(items), localFileMissing)
	}

	bootstrap := sanitizeDo53(cfg.BootstrapDNS)
	if len(bootstrap) == 0 {
		bootstrap = sanitizeDo53(append(append([]string{}, cfg.Upstream.Local...), cfg.Upstream.Overseas...))
	}
	if len(bootstrap) == 0 {
		bootstrap = []string{"223.5.5.5:53", "8.8.8.8:53", "1.1.1.1:53"}
	}
	log.Infof("bootstrap_dns loaded count=%d", len(bootstrap))

	dohBootstrap := sanitizeDo53(cfg.DoHBootstrapDNS)
	if len(dohBootstrap) == 0 {
		dohBootstrap = append([]string(nil), bootstrap...)
	}
	if len(dohBootstrap) == 0 {
		dohBootstrap = []string{"8.8.8.8:53", "1.1.1.1:53"}
	}
	log.Infof("doh_bootstrap_dns effective count=%d", len(dohBootstrap))

	upstreams, err := newUpstreamManager(cfg, log, bootstrap, dohBootstrap)
	if err != nil {
		return nil, err
	}

	responseCache, err := newResponseCache(cfg.Cache.Response.FilePath, cfg.Cache.Response.MaxEntries, cfg.staleTTL, cfg.nxdomainTTL, cfg.Cache.Response.Enabled, log)
	if err != nil {
		return nil, err
	}
	resultCache, err := newResultCache(cfg.Cache.ResponseResult.FilePath, cfg.Cache.ResponseResult.MaxEntries, time.Duration(cfg.Cache.ResponseResult.IPIdleDays)*24*time.Hour, cfg.Cache.ResponseResult.Enabled, log)
	if err != nil {
		return nil, err
	}

	s := &dnsServer{
		cfg:           cfg,
		log:           log,
		upstreams:     upstreams,
		responseCache: responseCache,
		resultCache:   resultCache,
		localOnly:     localOnly,
		localDomains:  localDomains,
	}
	go s.startLocalDomainUpdater(localFileMissing)
	go cleanupLogs(cfg.Log.Dir, cfg.Log.CleanupHours, log)
	return s, nil
}

func (s *dnsServer) Start(ctx context.Context) error {
	handler := dns.HandlerFunc(s.handleDNS)
	udp := &dns.Server{Addr: s.cfg.Server.Listen, Net: "udp", Handler: handler}
	tcp := &dns.Server{Addr: s.cfg.Server.Listen, Net: "tcp", Handler: handler}

	errCh := make(chan error, 2)
	go func() {
		s.log.Infof("starting UDP DNS server addr=%s", s.cfg.Server.Listen)
		errCh <- udp.ListenAndServe()
	}()
	go func() {
		s.log.Infof("starting TCP DNS server addr=%s", s.cfg.Server.Listen)
		errCh <- tcp.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = udp.ShutdownContext(shutdownCtx)
		_ = tcp.ShutdownContext(shutdownCtx)
		return nil
	case err := <-errCh:
		return err
	}
}

func (s *dnsServer) handleDNS(w dns.ResponseWriter, req *dns.Msg) {
	start := time.Now()
	resp := s.resolve(req)
	_ = w.WriteMsg(resp)
	qname, qtype, qclass := questionInfo(req)
	s.log.Queryf("%.3fms QUERY %s %s %s rcode=%s ips=%s", float64(time.Since(start).Microseconds())/1000, qname, dns.TypeToString[qtype], dns.ClassToString[qclass], dns.RcodeToString[resp.Rcode], strings.Join(extractA(resp), ","))
}

func (s *dnsServer) resolve(req *dns.Msg) *dns.Msg {
	if len(req.Question) == 0 {
		return servfail(req)
	}
	q := req.Question[0]
	key := makeKey(q)
	if q.Qtype != dns.TypeA {
		return s.resolveNoCache(req)
	}

	if cached, expired, ok := s.responseCache.Get(key, req); ok {
		if expired {
			reqCopy := req.Copy()
			go func() {
				_ = s.resolveFresh(reqCopy)
			}()
		}
		return cached
	}
	return s.resolveFresh(req)
}

func (s *dnsServer) resolveNoCache(req *dns.Msg) *dns.Msg {
	ctx, cancel := context.WithTimeout(context.Background(), s.cfg.totalTimeout)
	defer cancel()
	qname := strings.ToLower(req.Question[0].Name)
	if s.localOnly.Match(qname) || s.matchLocalDomain(qname) {
		msg, _, err := s.upstreams.Query(ctx, categoryLocal, req)
		if err == nil && msg != nil {
			return msg
		}
		return servfail(req)
	}
	msg, _, err := s.upstreams.Query(ctx, categoryOverseas, req)
	if err == nil && msg != nil {
		return msg
	}
	return servfail(req)
}

func (s *dnsServer) resolveFresh(req *dns.Msg) *dns.Msg {
	ctx, cancel := context.WithTimeout(context.Background(), s.cfg.totalTimeout)
	defer cancel()
	qname := strings.ToLower(req.Question[0].Name)

	if s.localOnly.Match(qname) || s.matchLocalDomain(qname) {
		msg, upstream, err := s.upstreams.Query(ctx, categoryLocal, req)
		if err != nil || msg == nil {
			return servfail(req)
		}
		s.storeBasic(req, msg, upstream)
		return msg
	}

	key := makeKey(req.Question[0])
	if !s.resultCache.Exists(key) {
		msg, upstream, err := s.upstreams.Query(ctx, categoryOverseas, req)
		if err != nil || msg == nil {
			return servfail(req)
		}
		s.storeBasic(req, msg, upstream)
		s.storeResult(key, msg)
		return msg
	}
	return s.resolveWithResultCache(ctx, req, key)
}

type routeResult struct {
	msg      *dns.Msg
	upstream string
	err      error
	category string
}

func (s *dnsServer) resolveWithResultCache(ctx context.Context, req *dns.Msg, key string) *dns.Msg {
	ch := make(chan routeResult, 2)
	go func() {
		msg, upstream, err := s.upstreams.Query(ctx, categoryLocal, req)
		ch <- routeResult{msg: msg, upstream: upstream, err: err, category: categoryLocal}
	}()
	go func() {
		msg, upstream, err := s.upstreams.Query(ctx, categoryOverseas, req)
		ch <- routeResult{msg: msg, upstream: upstream, err: err, category: categoryOverseas}
	}()

	var localResp *routeResult
	for received := 0; received < 2; received++ {
		select {
		case <-ctx.Done():
			if localResp != nil && hasA(localResp.msg) {
				setAllTTL(localResp.msg, uint32(s.cfg.staleTTL.Seconds()))
				return localResp.msg
			}
			return servfail(req)
		case res := <-ch:
			if res.err != nil || res.msg == nil {
				continue
			}
			if res.category == categoryOverseas {
				s.storeBasic(req, res.msg, res.upstream)
				s.storeResult(key, res.msg)
				return res.msg
			}
			localResp = &res
			if hasA(res.msg) && s.resultCache.Consistent(key, extractA(res.msg)) {
				setAllTTL(res.msg, uint32(s.cfg.staleTTL.Seconds()))
				go s.refreshOverseasAndStore(req.Copy(), key)
				return res.msg
			}
		}
	}
	if localResp != nil && hasA(localResp.msg) {
		setAllTTL(localResp.msg, uint32(s.cfg.staleTTL.Seconds()))
		return localResp.msg
	}
	return servfail(req)
}

func (s *dnsServer) refreshOverseasAndStore(req *dns.Msg, key string) {
	ctx, cancel := context.WithTimeout(context.Background(), s.cfg.totalTimeout)
	defer cancel()
	// Must use Query (not queryCategory) so this joins the same singleflight as the
	// concurrent overseas goroutine started in resolveWithResultCache.
	msg, upstream, err := s.upstreams.Query(ctx, categoryOverseas, req)
	if err == nil && msg != nil {
		s.storeBasic(req, msg, upstream)
		s.storeResult(key, msg)
	}
}

func (s *dnsServer) storeBasic(req, msg *dns.Msg, upstream string) {
	if s.responseCache.Put(makeKey(req.Question[0]), req, msg, upstream) {
		s.log.Debugf("response cache updated qname=%s upstream=%s", req.Question[0].Name, upstream)
	}
}

func (s *dnsServer) storeResult(key string, msg *dns.Msg) {
	ips := extractA(msg)
	if len(ips) == 0 {
		return
	}
	s.resultCache.Put(key, ips)
}

func (s *dnsServer) startLocalDomainUpdater(immediate bool) {
	cfg := s.cfg.Routing.LocalDomain
	if cfg.SourceURL == "" || cfg.FilePath == "" {
		return
	}
	interval := time.Duration(cfg.UpdateIntervalHours) * time.Hour
	if interval <= 0 {
		interval = 24 * time.Hour
	}
	if immediate {
		s.updateLocalDomains()
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for range ticker.C {
		s.updateLocalDomains()
	}
}

func (s *dnsServer) updateLocalDomains() {
	cfg := s.cfg.Routing.LocalDomain
	s.log.Infof("updating local_domains url=%s", cfg.SourceURL)
	b, err := downloadWithBootstrap(cfg.SourceURL, s.upstreams.bootstrapDNS)
	if err != nil {
		s.log.Warnf("download local_domains failed url=%s err=%v", cfg.SourceURL, err)
		return
	}
	if err := os.MkdirAll(filepath.Dir(cfg.FilePath), 0o755); err != nil {
		s.log.Warnf("create local_domains directory failed err=%v", err)
		return
	}
	if err := os.WriteFile(cfg.FilePath, b, 0o644); err != nil {
		s.log.Warnf("write local_domains failed path=%s err=%v", cfg.FilePath, err)
		return
	}
	items, err := parseDomainList(string(b))
	if err != nil {
		s.log.Warnf("parse local_domains failed err=%v", err)
		return
	}
	s.domainMu.Lock()
	s.localDomains = newMatcher(items)
	s.domainMu.Unlock()
	s.log.Infof("local_domains updated count=%d", len(items))
}

func (s *dnsServer) matchLocalDomain(qname string) bool {
	s.domainMu.RLock()
	defer s.domainMu.RUnlock()
	return s.localDomains.Match(qname)
}
