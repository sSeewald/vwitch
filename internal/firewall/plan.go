// Package firewall builds vwitch's nftables state. It owns only the tables
// "inet vwitch" and "ip vwitch_nat" and never flushes the ruleset, so other
// tools (e.g. NetBird) keep their tables. Rule building is pure; Apply
// (linux) replaces both tables atomically.
package firewall

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

// Owned table names.
const (
	TableFilter = "vwitch"     // family inet
	TableNAT    = "vwitch_nat" // family ip
)

// Chain identifies a base chain.
type Chain string

const (
	ChainInput       Chain = "input"
	ChainForward     Chain = "forward"
	ChainPrerouting  Chain = "prerouting"
	ChainPostrouting Chain = "postrouting"
)

// Verdict is the action of a rule.
type Verdict string

const (
	Accept     Verdict = "accept"
	Drop       Verdict = "drop"
	DNAT       Verdict = "dnat"
	Masquerade Verdict = "masquerade"
	Reject     Verdict = "reject"
	Log        Verdict = "log" // rate limited nflog, the rule continues
)

// IP protocol numbers.
const (
	ProtoICMP uint8 = 1
	ProtoTCP  uint8 = 6
	ProtoUDP  uint8 = 17
)

// Plan is the input for rule generation.
type Plan struct {
	AWGIfaces     []string // every ingress interface
	Isolated      []string // ingress interfaces whose clients reach no other client
	ServerAddr    netip.Addr
	ClientNet     netip.Prefix
	PortalPort    uint16
	EgressIfaces  []string
	DirectClients []netip.Addr
	PortalClients []netip.Addr
	AdminPort     uint16
	AdminIfaces   []string
	LockdownSSH   bool
}

// Rule is a declarative nftables rule.
type Rule struct {
	Chain         Chain
	IPv6          bool // match IPv6 packets only
	IIF, OIF      string
	OIFNot        []string
	IIFNot        []string
	Saddr         netip.Prefix
	Daddr         netip.Addr // a single destination address
	Proto         uint8
	DPort         uint16
	CtEstablished bool
	CtNew         bool
	Set           *SetMatch
	Verdict       Verdict
	LogPrefix     string
	NATAddr       netip.Addr
	NATPort       uint16
}

// Rules returns the full desired ruleset in chain order.
func (p Plan) Rules() []Rule {
	var rs []Rule
	add := func(r Rule) { rs = append(rs, r) }
	ings := p.AWGIfaces
	each := func(fn func(awg string)) {
		for _, a := range ings {
			fn(a)
		}
	}

	// input: admin port (and SSH with lockdown) only on admin interfaces;
	// these come first so an ingress can be an admin interface if configured
	p.restrictPort(add, p.AdminPort, nil)
	if p.LockdownSSH {
		p.restrictPort(add, 22, ings) // SSH never via a VPN ingress
	}
	// clients may only reach the portal and DNS (and ping the server)
	each(func(awg string) {
		add(Rule{Chain: ChainInput, IIF: awg, CtEstablished: true, Verdict: Accept})
		add(Rule{Chain: ChainInput, IIF: awg, Proto: ProtoTCP, DPort: p.PortalPort, Verdict: Accept})
		for _, proto := range []uint8{ProtoUDP, ProtoTCP} {
			add(Rule{Chain: ChainInput, IIF: awg, Proto: proto, DPort: 53, Verdict: Accept})
		}
		add(Rule{Chain: ChainInput, IIF: awg, Proto: ProtoICMP, Verdict: Accept})
		add(Rule{Chain: ChainInput, IIF: awg, Verdict: Drop})
	})
	// the portal and DNS on the server address serve only the tunnel: the
	// host accepts packets for any local address on any interface, so a
	// neighbour that routes the client net to the server must not reach them
	local := append(slices.Clone(ings), "lo")
	for _, pp := range []struct {
		proto uint8
		port  uint16
	}{{ProtoTCP, p.PortalPort}, {ProtoUDP, 53}, {ProtoTCP, 53}} {
		add(Rule{Chain: ChainInput, IIFNot: local, Daddr: p.ServerAddr, Proto: pp.proto, DPort: pp.port, Verdict: Drop})
	}

	// forward: client traffic leaves only through allowed exits; clients
	// reach each other only between ingresses that are not isolated
	each(func(awg string) { add(Rule{Chain: ChainForward, IIF: awg, IPv6: true, Verdict: Drop}) })
	each(func(awg string) { add(Rule{Chain: ChainForward, OIF: awg, CtEstablished: true, Verdict: Accept}) })
	each(func(from string) {
		for _, to := range ings {
			if !slices.Contains(p.Isolated, from) && !slices.Contains(p.Isolated, to) {
				add(Rule{Chain: ChainForward, IIF: from, OIF: to, Verdict: Accept})
			}
		}
	})
	each(func(awg string) {
		for _, e := range p.EgressIfaces {
			add(Rule{Chain: ChainForward, IIF: awg, OIF: e, Verdict: Accept})
		}
	})
	each(func(awg string) {
		for _, c := range p.DirectClients {
			add(Rule{Chain: ChainForward, IIF: awg, Saddr: host(c), OIFNot: ings, Verdict: Accept})
		}
	})
	each(func(awg string) { add(Rule{Chain: ChainForward, IIF: awg, Verdict: Drop}) })
	each(func(awg string) { add(Rule{Chain: ChainForward, OIF: awg, Verdict: Drop}) })

	// nat: all client DNS goes to vwitch's forwarder, offline HTTP to the
	// portal; masquerade everything leaving
	each(func(awg string) {
		for _, proto := range []uint8{ProtoUDP, ProtoTCP} {
			add(Rule{Chain: ChainPrerouting, IIF: awg, Proto: proto, DPort: 53, Verdict: DNAT, NATAddr: p.ServerAddr})
		}
		for _, c := range p.PortalClients {
			add(Rule{Chain: ChainPrerouting, IIF: awg, Saddr: host(c), Proto: ProtoTCP, DPort: 80,
				Verdict: DNAT, NATAddr: p.ServerAddr, NATPort: p.PortalPort})
		}
	})
	add(Rule{Chain: ChainPostrouting, Saddr: p.ClientNet, OIFNot: ings, Verdict: Masquerade})
	return rs
}

// restrictPort allows tcp port only on admin interfaces, except skip.
func (p Plan) restrictPort(add func(Rule), port uint16, skip []string) {
	if port == 0 {
		return
	}
	for _, i := range p.AdminIfaces {
		if slices.Contains(skip, i) {
			continue
		}
		add(Rule{Chain: ChainInput, IIF: i, Proto: ProtoTCP, DPort: port, Verdict: Accept})
	}
	add(Rule{Chain: ChainInput, Proto: ProtoTCP, DPort: port, Verdict: Drop})
}

// logRate limits logged block hits per rule (packets per second).
const logRate = 20

func host(a netip.Addr) netip.Prefix { return netip.PrefixFrom(a, 32) }

// Table returns the table a chain belongs to.
func (c Chain) Table() string {
	if c == ChainPrerouting || c == ChainPostrouting {
		return TableNAT
	}
	return TableFilter
}

// String renders the rule in nft syntax.
func (r Rule) String() string {
	var parts []string
	if r.IPv6 {
		parts = append(parts, "meta nfproto ipv6")
	}
	if r.IIF != "" {
		parts = append(parts, fmt.Sprintf("iifname %q", r.IIF))
	}
	if r.OIF != "" {
		parts = append(parts, fmt.Sprintf("oifname %q", r.OIF))
	}
	for _, i := range r.OIFNot {
		parts = append(parts, fmt.Sprintf("oifname != %q", i))
	}
	for _, i := range r.IIFNot {
		parts = append(parts, fmt.Sprintf("iifname != %q", i))
	}
	if r.Saddr.IsValid() {
		if r.Saddr.IsSingleIP() {
			parts = append(parts, "ip saddr "+r.Saddr.Addr().String())
		} else {
			parts = append(parts, "ip saddr "+r.Saddr.String())
		}
	}
	if r.Daddr.IsValid() {
		parts = append(parts, "ip daddr "+r.Daddr.String())
	}
	if r.CtEstablished {
		parts = append(parts, "ct state established,related")
	}
	if r.CtNew {
		parts = append(parts, "ct state new")
	}
	if s := r.Set; s != nil {
		fam, dir, op := "ip", "saddr", ""
		if s.IPv6 {
			fam = "ip6"
		}
		if s.Dst {
			dir = "daddr"
		}
		if s.Invert {
			op = "!= "
		}
		parts = append(parts, fmt.Sprintf("%s %s %s@%s", fam, dir, op, s.Set))
	}
	switch {
	case r.DPort != 0:
		parts = append(parts, fmt.Sprintf("%s dport %d", protoName(r.Proto), r.DPort))
	case r.Proto != 0:
		parts = append(parts, "meta l4proto "+protoName(r.Proto))
	}
	switch r.Verdict {
	case DNAT:
		to := r.NATAddr.String()
		if r.NATPort != 0 {
			to = fmt.Sprintf("%s:%d", to, r.NATPort)
		}
		parts = append(parts, "dnat to "+to)
	case Log:
		parts = append(parts, fmt.Sprintf("limit rate %d/second log prefix %q group %d", logRate, r.LogPrefix, LogGroup))
	default:
		parts = append(parts, string(r.Verdict))
	}
	return strings.Join(parts, " ")
}

// Render returns the ruleset as nft script (for status output and tests).
func Render(rules []Rule) string {
	var b strings.Builder
	for _, t := range []struct {
		family, name string
		chains       []Chain
	}{
		{"inet", TableFilter, []Chain{ChainInput, ChainForward}},
		{"ip", TableNAT, []Chain{ChainPrerouting, ChainPostrouting}},
	} {
		fmt.Fprintf(&b, "table %s %s {\n", t.family, t.name)
		for _, c := range t.chains {
			fmt.Fprintf(&b, "  chain %s {\n", c)
			for _, r := range rules {
				if r.Chain == c {
					fmt.Fprintf(&b, "    %s\n", r)
				}
			}
			b.WriteString("  }\n")
		}
		b.WriteString("}\n")
	}
	return b.String()
}

func protoName(p uint8) string {
	switch p {
	case ProtoTCP:
		return "tcp"
	case ProtoUDP:
		return "udp"
	case ProtoICMP:
		return "icmp"
	}
	return fmt.Sprint(p)
}
