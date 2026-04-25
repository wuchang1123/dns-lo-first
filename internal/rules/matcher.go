package rules

import (
	"bufio"
	"os"
	"strings"

	"golang.org/x/net/idna"
)

type Matcher struct {
	apex   map[string]struct{}
	strict map[string]struct{}
}

func NewMatcher(patterns []string) *Matcher {
	m := &Matcher{
		apex:   map[string]struct{}{},
		strict: map[string]struct{}{},
	}
	for _, p := range patterns {
		m.Add(p)
	}
	return m
}

func (m *Matcher) Add(pattern string) {
	p := Normalize(pattern)
	if p == "" {
		return
	}
	if strings.HasPrefix(p, "*.") {
		p = strings.TrimPrefix(p, "*.")
		if p != "" {
			m.strict[p] = struct{}{}
		}
		return
	}
	m.apex[p] = struct{}{}
}

func (m *Matcher) Match(name string) bool {
	n := Normalize(name)
	if n == "" {
		return false
	}
	if _, ok := m.apex[n]; ok {
		return true
	}
	parts := strings.Split(n, ".")
	for i := 1; i < len(parts); i++ {
		suffix := strings.Join(parts[i:], ".")
		if _, ok := m.apex[suffix]; ok {
			return true
		}
		if _, ok := m.strict[suffix]; ok {
			return true
		}
	}
	return false
}

func Normalize(name string) string {
	n := strings.TrimSpace(strings.ToLower(name))
	n = strings.TrimSuffix(n, ".")
	if n == "" {
		return ""
	}
	ascii, err := idna.Lookup.ToASCII(n)
	if err == nil {
		n = ascii
	}
	return n
}

func LoadDomainFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	var domains []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		domains = append(domains, ParseDomainLine(scanner.Text())...)
	}
	return domains, scanner.Err()
}

func ParseDomainLine(line string) []string {
	s := strings.TrimSpace(line)
	if s == "" || strings.HasPrefix(s, "#") {
		return nil
	}
	if idx := strings.Index(s, "#"); idx >= 0 {
		s = strings.TrimSpace(s[:idx])
	}
	if strings.HasPrefix(s, "server=/") {
		return parseDnsmasqDomains(s)
	}
	if strings.HasPrefix(s, "ipset=/") || strings.HasPrefix(s, "nftset=/") {
		return parseDnsmasqDomains(s)
	}
	if d := Normalize(s); d != "" {
		return []string{d}
	}
	return nil
}

func parseDnsmasqDomains(line string) []string {
	parts := strings.Split(line, "/")
	if len(parts) < 3 {
		return nil
	}
	var domains []string
	for _, part := range parts[1 : len(parts)-1] {
		if d := Normalize(strings.TrimPrefix(part, ".")); d != "" {
			domains = append(domains, d)
		}
	}
	return domains
}
