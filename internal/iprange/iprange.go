// Package iprange handles inclusive address ranges: merging them and the
// interval form nftables sets use.
package iprange

import (
	"cmp"
	"net/netip"
	"slices"
)

// Range is an inclusive address range of one family.
type Range struct{ From, To netip.Addr }

// FromPrefix returns the range a prefix covers.
func FromPrefix(p netip.Prefix) Range {
	p = p.Masked()
	from := p.Addr()
	to := from.As16()
	bits := p.Bits()
	if from.Is4() {
		bits += 96
	}
	for i := bits; i < 128; i++ {
		to[i/8] |= 0x80 >> (i % 8)
	}
	t := netip.AddrFrom16(to)
	if from.Is4() {
		t = t.Unmap()
	}
	return Range{from, t}
}

// Contains reports whether a lies in r.
func (r Range) Contains(a netip.Addr) bool { return r.From.Compare(a) <= 0 && a.Compare(r.To) <= 0 }

// Merge sorts ranges and joins overlapping and adjacent ones. IPv4 sorts
// before IPv6.
func Merge(rs []Range) []Range {
	rs = slices.Clone(rs)
	slices.SortFunc(rs, func(a, b Range) int { return cmp.Or(a.From.Compare(b.From), a.To.Compare(b.To)) })
	var out []Range
	for _, r := range rs {
		if n := len(out); n > 0 && out[n-1].To.Is4() == r.From.Is4() {
			last := &out[n-1]
			if next := last.To.Next(); r.From.Compare(last.To) <= 0 || (next.IsValid() && next == r.From) {
				if r.To.Compare(last.To) > 0 {
					last.To = r.To
				}
				continue
			}
		}
		out = append(out, r)
	}
	return out
}

// Subtract removes the parts of rs covered by cut. Both may be unsorted.
func Subtract(rs, cut []Range) []Range {
	rs, cut = Merge(rs), Merge(cut)
	var out []Range
	for _, r := range rs {
		cur := r
		ok := true
		for _, c := range cut {
			if c.From.Is4() != cur.From.Is4() || c.To.Compare(cur.From) < 0 || c.From.Compare(cur.To) > 0 {
				continue
			}
			if c.From.Compare(cur.From) > 0 {
				out = append(out, Range{cur.From, c.From.Prev()})
			}
			if c.To.Compare(cur.To) >= 0 {
				ok = false
				break
			}
			cur.From = c.To.Next()
		}
		if ok {
			out = append(out, cur)
		}
	}
	return out
}
