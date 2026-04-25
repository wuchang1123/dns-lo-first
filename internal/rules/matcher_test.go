package rules

import "testing"

func TestParseDomainLineDnsmasqMultipleDomains(t *testing.T) {
	got := ParseDomainLine("server=/mi-img5.com/mi-static.com/mi.com/mi0.cc/114.114.114.114")
	want := []string{"mi-img5.com", "mi-static.com", "mi.com", "mi0.cc"}
	if len(got) != len(want) {
		t.Fatalf("got %d domains, want %d: %#v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestMatcherMatchesSubdomainFromParsedDnsmasqLine(t *testing.T) {
	m := NewMatcher(ParseDomainLine("server=/mi-img5.com/mi-static.com/mi.com/mi0.cc/114.114.114.114"))
	if !m.Match("api2.mina.mi.com") {
		t.Fatal("expected api2.mina.mi.com to match mi.com")
	}
}
