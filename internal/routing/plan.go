// Package routing turns selection results into policy routing: one table per
// egress and ip rules per client. Plan building is pure; Apply (linux) syncs
// it to the kernel and touches only rules in vwitch's own priority slots.
package routing

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

// Rule priorities owned by vwitch. They sit before NetBird's rules (105+)
// and the default main rule (32766).
const (
	PrioProbe       = 60 // health probes bound to an egress interface
	PrioLocal       = 70 // traffic to the client network stays local
	PrioClient      = 80 // per-client exit
	PrioUnreachable = 99 // fail-safe: everything else from clients dies here
)

// OwnedPriorities lists every priority vwitch manages.
var OwnedPriorities = []int{PrioProbe, PrioLocal, PrioClient, PrioUnreachable}

// TableMain is the kernel's main table, used for the direct exit.
const TableMain = 254

// Egress is a routed egress interface.
type Egress struct {
	Iface string
	Table int
}

// Client is one client's exit. Table 0 means no exit (block or portal).
type Client struct {
	Addr  netip.Addr
	Table int
}

// Plan is the desired routing state.
type Plan struct {
	ClientNet netip.Prefix
	Egresses  []Egress
	Clients   []Client
}

// Rule is a desired ip rule.
type Rule struct {
	Priority    int
	Src         netip.Prefix
	Dst         netip.Prefix
	OIF         string
	Table       int
	Unreachable bool
}

// Route is a desired default route in an egress table.
type Route struct {
	Table int
	Iface string
}

// Rules returns the desired ip rules in a stable order.
func (p Plan) Rules() []Rule {
	var rs []Rule
	for _, e := range p.Egresses {
		rs = append(rs, Rule{Priority: PrioProbe, OIF: e.Iface, Table: e.Table})
	}
	rs = append(rs, Rule{Priority: PrioLocal, Dst: p.ClientNet, Table: TableMain})
	for _, c := range p.Clients {
		if c.Table != 0 {
			rs = append(rs, Rule{Priority: PrioClient, Src: netip.PrefixFrom(c.Addr, 32), Table: c.Table})
		}
	}
	rs = append(rs, Rule{Priority: PrioUnreachable, Src: p.ClientNet, Unreachable: true})
	slices.SortStableFunc(rs, func(a, b Rule) int { return a.Priority - b.Priority })
	return rs
}

// Routes returns the default routes of all egress tables.
func (p Plan) Routes() []Route {
	rs := make([]Route, 0, len(p.Egresses))
	for _, e := range p.Egresses {
		rs = append(rs, Route{Table: e.Table, Iface: e.Iface})
	}
	return rs
}

// Key identifies a rule for diffing.
func (r Rule) Key() string { return r.String() }

// String renders the rule like `ip rule`.
func (r Rule) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%d:", r.Priority)
	if r.Src.IsValid() {
		fmt.Fprintf(&b, " from %s", r.Src)
	} else {
		b.WriteString(" from all")
	}
	if r.Dst.IsValid() {
		fmt.Fprintf(&b, " to %s", r.Dst)
	}
	if r.OIF != "" {
		fmt.Fprintf(&b, " oif %s", r.OIF)
	}
	if r.Unreachable {
		b.WriteString(" unreachable")
	} else {
		fmt.Fprintf(&b, " lookup %d", r.Table)
	}
	return b.String()
}
