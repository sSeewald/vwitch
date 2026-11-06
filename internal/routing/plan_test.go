package routing

import (
	"net/netip"
	"strings"
	"testing"
)

func TestPlanRules(t *testing.T) {
	p := Plan{
		ClientNet: netip.MustParsePrefix("10.8.0.0/24"),
		Egresses:  []Egress{{Iface: "vwe1", Table: 51821}},
		Clients: []Client{
			{Addr: netip.MustParseAddr("10.8.0.2"), Table: 51821},
			{Addr: netip.MustParseAddr("10.8.0.3"), Table: TableMain},
			{Addr: netip.MustParseAddr("10.8.0.4")}, // portal
			{Addr: netip.MustParseAddr("10.8.0.5")}, // blocked
		},
	}
	var got []string
	for _, r := range p.Rules() {
		got = append(got, r.String())
	}
	want := []string{
		"60: from all oif vwe1 lookup 51821",
		"70: from all to 10.8.0.0/24 lookup 254",
		"80: from 10.8.0.2/32 lookup 51821",
		"80: from 10.8.0.3/32 lookup 254",
		"99: from 10.8.0.0/24 unreachable",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("got:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestPlanAlwaysFailSafe(t *testing.T) {
	// Even an empty plan must end with the unreachable rule.
	rs := Plan{ClientNet: netip.MustParsePrefix("10.8.0.0/24")}.Rules()
	last := rs[len(rs)-1]
	if !last.Unreachable || last.Priority != PrioUnreachable {
		t.Fatalf("last rule %v", last)
	}
}

func TestPlanDomains(t *testing.T) {
	p := Plan{
		ClientNet: netip.MustParsePrefix("10.8.0.0/24"),
		Clients:   []Client{{Addr: netip.MustParseAddr("10.8.0.2"), Table: 51821}},
		Domains:   []Domain{{Dst: netip.MustParseAddr("142.250.0.1"), Table: 51822}},
		Blocked:   []netip.Addr{netip.MustParseAddr("10.8.0.5")},
	}
	var got []string
	for _, r := range p.Rules() {
		got = append(got, r.String())
	}
	want := []string{
		"70: from all to 10.8.0.0/24 lookup 254",
		"72: from 10.8.0.5/32 unreachable",
		"75: from 10.8.0.0/24 to 142.250.0.1/32 lookup 51822",
		"80: from 10.8.0.2/32 lookup 51821",
		"99: from 10.8.0.0/24 unreachable",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("got:\n%s", strings.Join(got, "\n"))
	}
	// without domain routes no block rules are needed
	p.Domains = nil
	for _, r := range p.Rules() {
		if r.Priority == PrioBlocked {
			t.Fatal("block rule without domain routes")
		}
	}
}
