package firewall

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/sseewald/vwitch/internal/blocking"
	"github.com/sseewald/vwitch/internal/iprange"
)

func rng(a, b string) iprange.Range {
	return iprange.Range{From: netip.MustParseAddr(a), To: netip.MustParseAddr(b)}
}

func TestBlockPlan(t *testing.T) {
	p := BlockPlan{AWGIfaces: []string{"awg0"}, Filters: []blocking.Filter{{Source: "region", Outgoing: true, Incoming: true,
		Ranges: []iprange.Range{rng("5.8.0.0", "5.8.255.255"), rng("10.0.0.0", "10.0.0.255"), rng("2a00::", "2a00::ff")}}}}
	sets, rules := p.Build()
	if len(sets) != 2 || len(sets[0].Ranges) != 1 || sets[0].Ranges[0] != rng("5.8.0.0", "5.8.255.255") || len(sets[1].Ranges) != 1 {
		t.Fatalf("private ranges must never be blocked: %+v", sets)
	}
	got := RenderBlock(sets, rules)
	for _, want := range []string{
		`iifname "awg0" ct state new ip daddr @f0_region_v4 limit rate 20/second log prefix "vw|region|out" group 7091`,
		`iifname "awg0" ct state new ip daddr @f0_region_v4 reject`,
		`iifname != "awg0" iifname != "lo" ct state new ip saddr @f0_region_v4 drop`,
		`iifname != "awg0" iifname != "lo" ct state new ip6 saddr @f0_region_v6 drop`,
		"set f0_region_v4 { 1 ranges",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in\n%s", want, got)
		}
	}

	// allow mode: everything except the countries and special ranges
	p.Filters[0].Allow, p.Filters[0].Incoming = true, false
	sets, rules = p.Build()
	got = RenderBlock(sets, rules)
	if !strings.Contains(got, `ip daddr != @f0_region_v4 reject`) || strings.Contains(got, "chain input {\n    i") {
		t.Fatalf("allow outgoing only:\n%s", got)
	}
	found := false
	for _, r := range sets[0].Ranges {
		found = found || r.Contains(netip.MustParseAddr("192.168.1.1"))
	}
	if !found {
		t.Fatal("allow set must contain the LAN ranges")
	}
}

func TestLogPrefix(t *testing.T) {
	s, in, ok := ParseLogPrefix(LogPrefix("region", true) + "\x00")
	if !ok || s != "region" || !in {
		t.Fatal(s, in, ok)
	}
	if _, _, ok := ParseLogPrefix("other"); ok {
		t.Fatal("foreign prefix")
	}
}
