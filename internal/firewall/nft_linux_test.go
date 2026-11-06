//go:build linux

package firewall

import (
	"net/netip"
	"testing"

	"github.com/google/nftables/expr"

	"github.com/sseewald/vwitch/internal/blocking"
	"github.com/sseewald/vwitch/internal/iprange"
)

func natOf(t *testing.T, r Rule) *expr.NAT {
	t.Helper()
	ex, err := Exprs(r, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ex {
		if n, ok := e.(*expr.NAT); ok {
			return n
		}
	}
	t.Fatal("no NAT expression")
	return nil
}

// Regression: a DNAT without port must not mark the port range as
// specified, otherwise the kernel rewrites the port to 0.
func TestDNATPortFlag(t *testing.T) {
	addr := netip.MustParseAddr("10.8.0.1")
	if n := natOf(t, Rule{Chain: ChainPrerouting, Verdict: DNAT, NATAddr: addr}); n.Specified || n.RegProtoMin != 0 {
		t.Fatalf("address-only dnat: %+v", n)
	}
	if n := natOf(t, Rule{Chain: ChainPrerouting, Verdict: DNAT, NATAddr: addr, NATPort: 80}); !n.Specified || n.RegProtoMin != 2 {
		t.Fatalf("dnat with port: %+v", n)
	}
}

func TestAllRulesCompile(t *testing.T) {
	p := testPlan()
	p.LockdownSSH = true
	for _, r := range p.Rules() {
		if _, err := Exprs(r, r.Chain.Table() == TableFilter); err != nil {
			t.Fatalf("%s: %v", r, err)
		}
	}
}

func TestBlockRulesCompile(t *testing.T) {
	p := BlockPlan{AWGIfaces: []string{"awg0"}, Filters: []blocking.Filter{
		{Source: "region", Outgoing: true, Incoming: true, Ranges: []iprange.Range{rng("5.8.0.0", "5.8.0.255")}},
		{Source: "region", Outgoing: true, Allow: true, Ranges: []iprange.Range{rng("2.160.0.0", "2.175.255.255")}},
	}}
	sets, rules := p.Build()
	for _, r := range rules {
		if _, err := exprs(r, true, nil); err != nil {
			t.Fatalf("%s: %v", r, err)
		}
	}
	el := intervalElements(sets[0].Ranges)
	if len(el) != 3 || !el[0].IntervalEnd || el[1].IntervalEnd || !el[2].IntervalEnd ||
		netip.AddrFrom4([4]byte(el[2].Key)) != netip.MustParseAddr("5.8.1.0") {
		t.Fatalf("interval encoding %+v", el)
	}
}
