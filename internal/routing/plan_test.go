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
