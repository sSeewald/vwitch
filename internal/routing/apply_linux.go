//go:build linux

package routing

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// Apply syncs routes and rules to the kernel. Order matters for the
// fail-safe: the unreachable rule is added before anything is removed.
func Apply(p Plan) error {
	var errs []error
	for _, r := range p.Routes() {
		if err := ensureDefaultRoute(r); err != nil {
			errs = append(errs, err)
		}
	}

	want := map[string]Rule{}
	for _, r := range p.Rules() {
		want[r.Key()] = r
	}
	have, err := ownedRules()
	if err != nil {
		return errors.Join(append(errs, err)...)
	}
	haveKeys := map[string]bool{}
	for _, h := range have {
		haveKeys[h.rule.Key()] = true
	}
	// add missing rules, lowest priority last so the fail-safe exists first
	desired := p.Rules()
	slices.Reverse(desired)
	for _, r := range desired {
		if haveKeys[r.Key()] {
			continue
		}
		if err := netlink.RuleAdd(toNetlink(r)); err != nil {
			errs = append(errs, fmt.Errorf("add rule %s: %w", r, err))
		}
	}
	for _, h := range have {
		if _, ok := want[h.rule.Key()]; ok {
			continue
		}
		if err := netlink.RuleDel(h.nl); err != nil {
			errs = append(errs, fmt.Errorf("delete rule %s: %w", h.rule, err))
		}
	}
	return errors.Join(errs...)
}

// FlushConntrack removes tracked connections originating from addrs so they
// re-route after an exit change.
func FlushConntrack(addrs []netip.Addr) error {
	if len(addrs) == 0 {
		return nil
	}
	var filters []netlink.CustomConntrackFilter
	for _, a := range addrs {
		f := &netlink.ConntrackFilter{}
		if err := f.AddIP(netlink.ConntrackOrigSrcIP, net.IP(a.AsSlice())); err != nil {
			return err
		}
		filters = append(filters, f)
	}
	_, err := netlink.ConntrackDeleteFilters(netlink.ConntrackTable, unix.AF_INET, filters...)
	return err
}

func ensureDefaultRoute(r Route) error {
	link, err := netlink.LinkByName(r.Iface)
	if err != nil {
		return fmt.Errorf("route table %d: %w", r.Table, err)
	}
	_, all, _ := net.ParseCIDR("0.0.0.0/0")
	return netlink.RouteReplace(&netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       all,
		Table:     r.Table,
		Scope:     netlink.SCOPE_LINK,
	})
}

type ownedRule struct {
	nl   *netlink.Rule
	rule Rule
}

func ownedRules() ([]ownedRule, error) {
	list, err := netlink.RuleList(unix.AF_INET)
	if err != nil {
		return nil, fmt.Errorf("list rules: %w", err)
	}
	var out []ownedRule
	for i := range list {
		nl := &list[i]
		if !slices.Contains(OwnedPriorities, nl.Priority) {
			continue
		}
		out = append(out, ownedRule{nl: nl, rule: fromNetlink(nl)})
	}
	return out, nil
}

func toNetlink(r Rule) *netlink.Rule {
	nl := netlink.NewRule()
	nl.Family = unix.AF_INET
	nl.Priority = r.Priority
	nl.Src = ipNet(r.Src)
	nl.Dst = ipNet(r.Dst)
	nl.OifName = r.OIF
	if r.Unreachable {
		nl.Type = unix.RTN_UNREACHABLE
	} else {
		nl.Table = r.Table
	}
	return nl
}

func fromNetlink(nl *netlink.Rule) Rule {
	r := Rule{Priority: nl.Priority, Src: prefix(nl.Src), Dst: prefix(nl.Dst), OIF: nl.OifName}
	// RuleList does not report the rule type; vwitch only creates rules
	// without a table for "unreachable", so a missing table identifies them.
	if nl.Type == unix.RTN_UNREACHABLE || nl.Table <= 0 {
		r.Unreachable = true
	} else {
		r.Table = nl.Table
	}
	return r
}

func ipNet(p netip.Prefix) *net.IPNet {
	if !p.IsValid() {
		return nil
	}
	return &net.IPNet{IP: net.IP(p.Addr().AsSlice()), Mask: net.CIDRMask(p.Bits(), 32)}
}

func prefix(n *net.IPNet) netip.Prefix {
	if n == nil {
		return netip.Prefix{}
	}
	a, ok := netip.AddrFromSlice(n.IP.To4())
	if !ok {
		return netip.Prefix{}
	}
	bits, _ := n.Mask.Size()
	if bits == 0 { // "from all"
		return netip.Prefix{}
	}
	return netip.PrefixFrom(a, bits)
}
