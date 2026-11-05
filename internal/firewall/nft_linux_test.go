//go:build linux

package firewall

import (
	"net/netip"
	"testing"

	"github.com/google/nftables/expr"
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
