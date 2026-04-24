package poison

import (
	"os"
	"strings"
)

// normalizeDomainForMatch 规范化域名用于列表匹配：小写、去首尾点与空标签，不处理 *。
func normalizeDomainForMatch(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimSuffix(s, ".")
	s = strings.TrimPrefix(s, ".")
	var parts []string
	for _, p := range strings.Split(s, ".") {
		if p != "" {
			parts = append(parts, p)
		}
	}
	return strings.Join(parts, ".")
}

func appendDomainPatternLine(raw string, explicit, wildcardOnly map[string]struct{}) {
	line := strings.TrimSpace(raw)
	if line == "" || strings.HasPrefix(line, "#") {
		return
	}
	isRFCWildcard := strings.HasPrefix(line, "*.")
	rest := line
	if isRFCWildcard {
		rest = strings.TrimSpace(strings.TrimPrefix(line, "*."))
		rest = strings.TrimPrefix(rest, ".")
	}
	d := normalizeDomainForMatch(rest)
	if d == "" {
		return
	}
	if isRFCWildcard {
		wildcardOnly[d] = struct{}{}
	} else {
		explicit[d] = struct{}{}
	}
}

func mergeDomainPatternMaps(dstE, dstW, srcE, srcW map[string]struct{}) {
	for k := range srcE {
		dstE[k] = struct{}{}
	}
	for k := range srcW {
		dstW[k] = struct{}{}
	}
}

func loadDomainPatternFile(path string) (explicit map[string]struct{}, wildcardOnly map[string]struct{}, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	explicit = make(map[string]struct{})
	wildcardOnly = make(map[string]struct{})
	for _, raw := range strings.Split(string(data), "\n") {
		appendDomainPatternLine(raw, explicit, wildcardOnly)
	}
	return explicit, wildcardOnly, nil
}

func domainMatchesPatternList(d string, explicit, wildcardOnly map[string]struct{}) bool {
	if d == "" {
		return false
	}
	for e := range explicit {
		if e == "" {
			continue
		}
		if d == e || (len(d) > len(e) && strings.HasSuffix(d, "."+e)) {
			return true
		}
	}
	for e := range wildcardOnly {
		if e == "" {
			continue
		}
		if len(d) > len(e) && strings.HasSuffix(d, "."+e) {
			return true
		}
	}
	return false
}

func (c *Checker) domainInSkipTLSVerifyList(domain string) bool {
	return domainMatchesPatternList(normalizeDomainForMatch(domain), c.tlsSkipVerifySet, c.tlsSkipVerifyWildcardOnly)
}
