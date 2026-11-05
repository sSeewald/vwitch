//go:build linux

package routing

import (
	"net/netip"
	"testing"
)

// Listed rules must produce the same keys as desired rules, otherwise
// Apply would delete and re-add them on every run (and briefly lose the
// fail-safe).
func TestNetlinkRoundTripKeys(t *testing.T) {
	p := Plan{
		ClientNet: netip.MustParsePrefix("10.8.0.0/24"),
		Egresses:  []Egress{{Iface: "vwe1", Table: 51821}},
		Clients:   []Client{{Addr: netip.MustParseAddr("10.8.0.2"), Table: 51821}},
	}
	for _, r := range p.Rules() {
		nl := toNetlink(r)
		if r.Unreachable {
			nl.Type = 0 // RuleList does not fill Type
			nl.Table = 0
		}
		if got := fromNetlink(nl); got.Key() != r.Key() {
			t.Errorf("round trip %q -> %q", r.Key(), got.Key())
		}
	}
}
