package asn

import (
	"net"
	"os"
	"strings"

	"dns-lo-first/internal/rules"
	"gopkg.in/yaml.v3"
)

type File struct {
	Version  int                 `yaml:"version"`
	Orgs     map[string]Org      `yaml:"orgs"`
	Suffixes []SuffixAssociation `yaml:"suffixes"`
}

type Org struct {
	Prefixes []string `yaml:"prefixes"`
}

type SuffixAssociation struct {
	Suffix string   `yaml:"suffix"`
	Org    string   `yaml:"org"`
	Orgs   []string `yaml:"orgs"`
}

type DB struct {
	orgs     map[string][]*net.IPNet
	suffixes []suffixRule
}

type suffixRule struct {
	suffix string
	orgs   []string
	strict bool
}

func Load(path string) (*DB, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f File
	if err := yaml.Unmarshal(b, &f); err != nil {
		return nil, err
	}
	db := &DB{orgs: map[string][]*net.IPNet{}}
	for org, data := range f.Orgs {
		key := strings.ToLower(strings.TrimSpace(org))
		for _, p := range data.Prefixes {
			_, n, err := net.ParseCIDR(strings.TrimSpace(p))
			if err == nil && n.IP.To4() != nil {
				db.orgs[key] = append(db.orgs[key], n)
			}
		}
	}
	for _, assoc := range f.Suffixes {
		suffix := rules.Normalize(assoc.Suffix)
		if suffix == "" {
			continue
		}
		orgs := assoc.Orgs
		if assoc.Org != "" {
			orgs = append(orgs, assoc.Org)
		}
		var normalized []string
		for _, org := range orgs {
			org = strings.ToLower(strings.TrimSpace(org))
			if org != "" {
				normalized = append(normalized, org)
			}
		}
		if len(normalized) > 0 {
			db.suffixes = append(db.suffixes, suffixRule{suffix: suffix, orgs: normalized})
		}
	}
	return db, nil
}

func (db *DB) Check(names []string, ips []net.IP) (known bool, good []net.IP) {
	if db == nil {
		return false, nil
	}
	var orgs []string
	for _, name := range names {
		if matched := db.matchOrgs(name); len(matched) > 0 {
			orgs = append(orgs, matched...)
		}
	}
	if len(orgs) == 0 {
		return false, nil
	}
	seen := map[string]struct{}{}
	for _, ip := range ips {
		ip4 := ip.To4()
		if ip4 == nil {
			continue
		}
		for _, org := range orgs {
			for _, n := range db.orgs[org] {
				if n.Contains(ip4) {
					key := ip4.String()
					if _, ok := seen[key]; !ok {
						good = append(good, ip4)
						seen[key] = struct{}{}
					}
				}
			}
		}
	}
	return true, good
}

func (db *DB) matchOrgs(name string) []string {
	n := rules.Normalize(name)
	if n == "" {
		return nil
	}
	var bestLen int
	var out []string
	for _, r := range db.suffixes {
		if n == r.suffix || strings.HasSuffix(n, "."+r.suffix) {
			if len(r.suffix) > bestLen {
				bestLen = len(r.suffix)
				out = append([]string{}, r.orgs...)
			}
		}
	}
	return out
}
