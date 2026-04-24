package poison

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"lo-dns/internal/logger"
)

// Check 对域名和IP列表进行判毒检查
func (c *Checker) Check(domain string, ips []net.IP, source string) *CheckResult {
	if !c.config.Enabled {
		return &CheckResult{Passed: true, Reason: "check disabled"}
	}

	start := time.Now()
	result := &CheckResult{
		Passed:     true,
		CheckedIPs: ips,
	}

	if len(ips) == 0 {
		result.Reason = "no IPs to check"
		result.Duration = time.Since(start)
		return result
	}

	if c.domainInSkipTLSVerifyList(domain) {
		result.Reason = "tls verify skipped (skip_tls_verify list)"
		result.Duration = time.Since(start)
		return result
	}

	if c.checklistEnabled && !c.domainInChecklist(domain) {
		result.Reason = "tls verify skipped (not in checklist)"
		result.Duration = time.Since(start)
		return result
	}

	var wg sync.WaitGroup
	resultChan := make(chan *tlsCheckResult, len(ips))

	for _, ip := range ips {
		wg.Add(1)
		go func(ip net.IP) {
			defer wg.Done()
			c.sem <- struct{}{}
			defer func() { <-c.sem }()

			checkResult := c.checkTLS(domain, ip, source)
			resultChan <- checkResult
		}(ip)
	}

	go func() {
		wg.Wait()
		close(resultChan)
	}()

	var failedChecks []*tlsCheckResult
	for r := range resultChan {
		if !r.success {
			failedChecks = append(failedChecks, r)
		}
	}

	result.Duration = time.Since(start)

	if len(failedChecks) > 0 {
		result.Passed = false
		result.Reason = fmt.Sprintf("TLS check failed for %d IPs", len(failedChecks))
		for _, f := range failedChecks {
			result.Reason += fmt.Sprintf(" [%s: %s]", f.ip, f.err)
		}
	} else {
		result.Reason = "all TLS checks passed"
	}

	return result
}

func (c *Checker) checkTLS(domain string, ip net.IP, source string) *tlsCheckResult {
	if c.domainInSkipTLSVerifyList(domain) {
		return &tlsCheckResult{ip: ip, success: true}
	}

	if c.checklistEnabled && !c.domainInChecklist(domain) {
		return &tlsCheckResult{ip: ip, success: true}
	}

	if passed, _, found := c.getFromCache(domain, ip); found {
		return &tlsCheckResult{
			ip:      ip,
			success: passed,
		}
	}

	result := &tlsCheckResult{
		ip:      ip,
		success: false,
	}

	if c.config.ASNEnabled {
		org := c.getOrgByDomain(domain)
		if org != "" {
			if !c.isIPInOrgPrefixes(ip, org) {
				result.err = fmt.Sprintf("IP不在%s的IP段内", org)
				c.setCache(domain, ip, false, result.err, source)
				return result
			}
		}
	}

	tlsDomain := domain
	if resolvedDomain := c.resolveIPToDomain(ip); resolvedDomain != "" {
		tlsDomain = resolvedDomain
		logger.Printf("[TLS DOMAIN] %s -> 使用反向查询域名 %s 进行TLS握手", domain, tlsDomain)
	}

	conf := &tls.Config{
		ServerName:         tlsDomain,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			certs := make([]*x509.Certificate, len(rawCerts))
			for i, rawCert := range rawCerts {
				cert, err := x509.ParseCertificate(rawCert)
				if err != nil {
					return err
				}
				certs[i] = cert
			}

			opts := x509.VerifyOptions{
				DNSName: domain,
			}
			if _, err := certs[0].Verify(opts); err == nil {
				return nil
			}

			currentDomain := domain
			for {
				if err := verifyCertDomain(certs[0], currentDomain); err == nil {
					return nil
				}
				parts := strings.Split(currentDomain, ".")
				if len(parts) <= 2 {
					break
				}
				currentDomain = strings.Join(parts[1:], ".")
			}

			return fmt.Errorf("certificate not valid for %s", domain)
		},
	}

	addr := net.JoinHostPort(ip.String(), fmt.Sprintf("%d", c.config.TLSPort))
	dialer := &net.Dialer{
		Timeout: time.Duration(c.config.TLSTimeout) * time.Second,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", addr, conf)
	if err != nil {
		result.err = fmt.Sprintf("TLS handshake failed: %v", err)
		c.setCache(domain, ip, false, result.err, source)
		return result
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		result.err = "no certificates found"
		c.setCache(domain, ip, false, result.err, source)
		return result
	}

	cert := state.PeerCertificates[0]
	if err := verifyCertDomain(cert, domain); err != nil {
		result.err = fmt.Sprintf("certificate domain mismatch: %v", err)
		c.setCache(domain, ip, false, result.err, source)
		return result
	}

	result.success = true
	c.setCache(domain, ip, true, "TLS handshake successful", source)
	return result
}

func verifyCertDomain(cert *x509.Certificate, domain string) error {
	for _, name := range cert.DNSNames {
		if matchDomain(name, domain) {
			return nil
		}
	}

	if matchDomain(cert.Subject.CommonName, domain) {
		return nil
	}

	return fmt.Errorf("domain %s not found in certificate", domain)
}

func matchDomain(pattern, domain string) bool {
	if pattern == domain {
		return true
	}

	if len(pattern) > 1 && pattern[0] == '*' {
		if pattern[1] == '.' {
			suffix := pattern[2:]
			if (len(domain) > len(suffix) && domain[len(domain)-len(suffix)-1:] == "."+suffix) || domain == suffix {
				return true
			}
		}
	}

	return false
}
