package main

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

type asnFile struct {
	Version int `yaml:"version"`
	Orgs    map[string]struct {
		Prefixes []string `yaml:"prefixes"`
	} `yaml:"orgs"`
	Suffixes []struct {
		Suffix string `yaml:"suffix"`
		Org    string `yaml:"org"`
	} `yaml:"suffixes"`
}

type asnDB struct {
	enabled bool

	// suffix -> org
	suffixOrg map[string]string
	// org -> prefixes
	orgPrefixes map[string][]netip.Prefix
	// suffixes ordered by length desc for longest-match
	suffixes []string
}

func loadASNDB(path string, enabled bool) (*asnDB, error) {
	db := &asnDB{enabled: enabled, suffixOrg: make(map[string]string), orgPrefixes: make(map[string][]netip.Prefix)}
	if !enabled {
		return db, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f asnFile
	if err := yaml.Unmarshal(b, &f); err != nil {
		return nil, err
	}
	for org, o := range f.Orgs {
		for _, raw := range o.Prefixes {
			raw = strings.TrimSpace(raw)
			if raw == "" {
				continue
			}
			p, err := netip.ParsePrefix(raw)
			if err != nil {
				return nil, fmt.Errorf("org %s prefix %q: %w", org, raw, err)
			}
			db.orgPrefixes[org] = append(db.orgPrefixes[org], p)
		}
	}
	for _, s := range f.Suffixes {
		suffix := strings.ToLower(strings.TrimSpace(s.Suffix))
		suffix = strings.TrimSuffix(suffix, ".")
		if suffix == "" || s.Org == "" {
			continue
		}
		db.suffixOrg[suffix] = s.Org
		db.suffixes = append(db.suffixes, suffix)
	}
	sort.Slice(db.suffixes, func(i, j int) bool {
		li := len(strings.Split(db.suffixes[i], "."))
		lj := len(strings.Split(db.suffixes[j], "."))
		if li == lj {
			return db.suffixes[i] > db.suffixes[j]
		}
		return li > lj
	})
	return db, nil
}

var (
	errASNNotMatched = errors.New("asn not matched")
	errASNNoPrefixes = errors.New("asn org has no prefixes")
)

func (db *asnDB) matchOrg(qname string) (string, error) {
	if db == nil || !db.enabled {
		return "", errASNNotMatched
	}
	name := strings.ToLower(strings.TrimSuffix(qname, "."))
	for _, suffix := range db.suffixes {
		if name == suffix || strings.HasSuffix(name, "."+suffix) {
			org := db.suffixOrg[suffix]
			if org == "" {
				break
			}
			return org, nil
		}
	}
	return "", errASNNotMatched
}

func (db *asnDB) polluted(qname string, ips []string) (bool, string, error) {
	org, err := db.matchOrg(qname)
	if err != nil {
		return false, "", err
	}
	prefixes := db.orgPrefixes[org]
	if len(prefixes) == 0 {
		return false, org, errASNNoPrefixes
	}
	for _, ipStr := range ips {
		addr, err := netip.ParseAddr(ipStr)
		if err != nil || !addr.Is4() {
			continue
		}
		for _, p := range prefixes {
			if p.Contains(addr) {
				return false, org, nil
			}
		}
	}
	// No IP matched any prefix => polluted
	return true, org, nil
}
