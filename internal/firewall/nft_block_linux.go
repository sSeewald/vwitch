//go:build linux

package firewall

import (
	"fmt"
	"net/netip"

	"github.com/google/nftables"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"

	"github.com/sseewald/vwitch/internal/iprange"
)

// elemsPerMessage keeps each netlink message well below the 64 KiB limit
// of a nested attribute (a range is two elements of up to ~40 bytes).
const elemsPerMessage = 600

// sendBuffer fits a batch with several 10,000 ranges.
const sendBuffer = 32 << 20

// ApplyBlock replaces the block table atomically, or removes it when
// there are no rules.
func ApplyBlock(sets []Set, rules []Rule) error {
	conn, err := nftables.New(nftables.WithSockOptions(func(c *netlink.Conn) error {
		raw, err := c.SyscallConn()
		if err != nil {
			return err
		}
		var serr error
		if err := raw.Control(func(fd uintptr) {
			serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUFFORCE, sendBuffer)
		}); err != nil {
			return err
		}
		return serr
	}))
	if err != nil {
		return fmt.Errorf("nftables: %w", err)
	}
	t := &nftables.Table{Family: nftables.TableFamilyINet, Name: TableBlock}
	conn.AddTable(t) // add+delete never fails, even if the table is missing
	conn.DelTable(t)
	if len(rules) == 0 {
		return flush(conn)
	}
	conn.AddTable(t)
	prio := *nftables.ChainPriorityFilter - 10 // before vwitch's own filter
	accept := nftables.ChainPolicyAccept
	chains := map[Chain]*nftables.Chain{
		ChainInput: conn.AddChain(&nftables.Chain{Name: string(ChainInput), Table: t, Type: nftables.ChainTypeFilter,
			Hooknum: nftables.ChainHookInput, Priority: &prio, Policy: &accept}),
		ChainForward: conn.AddChain(&nftables.Chain{Name: string(ChainForward), Table: t, Type: nftables.ChainTypeFilter,
			Hooknum: nftables.ChainHookForward, Priority: &prio, Policy: &accept}),
	}
	byName := map[string]*nftables.Set{}
	for _, s := range sets {
		key := nftables.TypeIPAddr
		if s.IPv6 {
			key = nftables.TypeIP6Addr
		}
		ns := &nftables.Set{Table: t, Name: s.Name, KeyType: key, Interval: true}
		if err := conn.AddSet(ns, nil); err != nil {
			return fmt.Errorf("set %s: %w", s.Name, err)
		}
		elems := intervalElements(s.Ranges)
		for i := 0; i < len(elems); i += elemsPerMessage {
			if err := conn.SetAddElements(ns, elems[i:min(i+elemsPerMessage, len(elems))]); err != nil {
				return fmt.Errorf("set %s: %w", s.Name, err)
			}
		}
		byName[s.Name] = ns
	}
	for _, r := range rules {
		c := chains[r.Chain]
		ex, err := exprs(r, true, byName)
		if err != nil {
			return fmt.Errorf("rule %q: %w", r, err)
		}
		conn.AddRule(&nftables.Rule{Table: t, Chain: c, Exprs: ex})
	}
	return flush(conn)
}

func flush(conn *nftables.Conn) error {
	if err := conn.Flush(); err != nil {
		return fmt.Errorf("nftables flush: %w", err)
	}
	return nil
}

// intervalElements encodes sorted, non-overlapping ranges the way nft
// does: a start element and an end marker one past the range. A range
// reaching the last address has no end marker.
func intervalElements(rs []iprange.Range) []nftables.SetElement {
	var out []nftables.SetElement
	for i, r := range rs {
		if i == 0 && !r.From.IsUnspecified() {
			out = append(out, nftables.SetElement{Key: zero(r.From).AsSlice(), IntervalEnd: true})
		}
		out = append(out, nftables.SetElement{Key: r.From.AsSlice()})
		if next := r.To.Next(); next.IsValid() {
			out = append(out, nftables.SetElement{Key: next.AsSlice(), IntervalEnd: true})
		}
	}
	return out
}

func zero(a netip.Addr) netip.Addr {
	if a.Is4() {
		return netip.IPv4Unspecified()
	}
	return netip.IPv6Unspecified()
}
