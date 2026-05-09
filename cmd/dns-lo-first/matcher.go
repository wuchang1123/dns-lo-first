package main

import (
	"net"
	"os"
	"strings"
)

type matcher struct {
	exact    map[string]struct{}
	wildcard map[string]struct{}
}

func newMatcher(items []string) *matcher {
	m := &matcher{exact: make(map[string]struct{}), wildcard: make(map[string]struct{})}
	for _, item := range items {
		item = strings.ToLower(strings.TrimSpace(item))
		item = strings.TrimSuffix(item, ".")
		if item == "" || strings.HasPrefix(item, "#") {
			continue
		}
		if strings.HasPrefix(item, "*.") {
			m.wildcard[strings.TrimPrefix(item, "*.")] = struct{}{}
			continue
		}
		m.exact[item] = struct{}{}
	}
	return m
}

func (m *matcher) Match(qname string) bool {
	name := strings.ToLower(strings.TrimSuffix(qname, "."))
	if _, ok := m.exact[name]; ok {
		return true
	}
	parts := strings.Split(name, ".")
	for i := 1; i < len(parts); i++ {
		suffix := strings.Join(parts[i:], ".")
		if _, ok := m.exact[suffix]; ok {
			return true
		}
		if _, ok := m.wildcard[suffix]; ok && i > 0 {
			return true
		}
	}
	return false
}

func loadDomainFile(path string) ([]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseDomainList(string(b))
}

func parseDomainList(s string) ([]string, error) {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if i := strings.Index(line, "#"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if strings.Contains(line, "/") {
			parts := strings.Split(line, "/")
			for _, part := range parts {
				if isDomainLike(part) {
					out = append(out, part)
					break
				}
			}
			continue
		}
		fields := strings.Fields(line)
		for _, field := range fields {
			if isDomainLike(field) {
				out = append(out, field)
				break
			}
		}
	}
	return out, nil
}

func isDomainLike(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" || strings.ContainsAny(s, ":/") || net.ParseIP(s) != nil {
		return false
	}
	return strings.Contains(s, ".")
}
