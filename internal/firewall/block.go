package firewall

import (
	"crypto/sha256"
	"fmt"
	"slices"
	"strings"

	"github.com/sseewald/vwitch/internal/blocking"
	"github.com/sseewald/vwitch/internal/iprange"
)

// TableBlock holds the address filters (family inet). It is separate from
// TableFilter so large sets are only rewritten when they change, and it
// is deleted when no filter is active.
const TableBlock = "vwitch_block"

// LogGroup is the nflog group of logged block hits.
const LogGroup = 7091

// LogPrefix tags a logged hit: "vw|<source>|<in|out>".
func LogPrefix(source string, incoming bool) string {
	dir := "out"
	if incoming {
		dir = "in"
	}
	return "vw|" + source + "|" + dir
}

// ParseLogPrefix reverses LogPrefix.
func ParseLogPrefix(p string) (source string, incoming, ok bool) {
	f := strings.Split(strings.TrimRight(p, "\x00 "), "|")
	if len(f) != 3 || f[0] != "vw" {
		return "", false, false
	}
	return f[1], f[2] == "in", true
}

// Set is a named interval set of one address family.
type Set struct {
	Name   string
	IPv6   bool
	Ranges []iprange.Range
}

// SetMatch matches the source or destination address against a set.
type SetMatch struct {
	Set    string
	IPv6   bool
	Dst    bool // match the destination, else the source
	Invert bool // not in the set
}

// BlockPlan is the input for the block table.
type BlockPlan struct {
	AWGIfaces []string // every ingress interface
	Filters   []blocking.Filter
}

// Build returns the sets and rules of the block table: outgoing filters
// apply to new client connections (forward), incoming ones to new
// connections to the server from anywhere but the VPN and loopback
// (input). Every hit is logged (rate limited) before it is rejected or
// dropped. Special ranges are never filtered.
func (p BlockPlan) Build() ([]Set, []Rule) {
	var sets []Set
	var rules []Rule
	for i, f := range p.Filters {
		ranges := iprange.Subtract(f.Ranges, blocking.Special)
		if f.Allow {
			ranges = iprange.Merge(append(f.Ranges, blocking.Special...))
		}
		var v4, v6 []iprange.Range
		for _, r := range ranges {
			if r.From.Is4() {
				v4 = append(v4, r)
			} else {
				v6 = append(v6, r)
			}
		}
		name := fmt.Sprintf("f%d_%s", i, f.Source)
		sets = append(sets, Set{Name: name + "_v4", Ranges: v4}, Set{Name: name + "_v6", IPv6: true, Ranges: v6})
		hit := func(r Rule, incoming bool, verdict Verdict) {
			log := r
			log.Verdict, log.LogPrefix = Log, LogPrefix(f.Source, incoming)
			r.Verdict = verdict
			rules = append(rules, log, r)
		}
		if f.Outgoing { // clients have no IPv6, it is dropped elsewhere
			for _, awg := range p.AWGIfaces {
				hit(Rule{Chain: ChainForward, IIF: awg, CtNew: true,
					Set: &SetMatch{Set: name + "_v4", Dst: true, Invert: f.Allow}}, false, Reject)
			}
		}
		if f.Incoming {
			for _, v6 := range []bool{false, true} {
				set := name + "_v4"
				if v6 {
					set = name + "_v6"
				}
				hit(Rule{Chain: ChainInput, IIFNot: append(slices.Clone(p.AWGIfaces), "lo"), CtNew: true,
					Set: &SetMatch{Set: set, IPv6: v6, Invert: f.Allow}}, true, Drop)
			}
		}
	}
	return sets, rules
}

// RenderBlock describes the block table for change detection and status
// output; sets are summarized by size and a hash of their ranges.
func RenderBlock(sets []Set, rules []Rule) string {
	var b strings.Builder
	fmt.Fprintf(&b, "table inet %s {\n", TableBlock)
	for _, s := range sets {
		h := sha256.New()
		for _, r := range s.Ranges {
			fmt.Fprintf(h, "%s-%s,", r.From, r.To)
		}
		fmt.Fprintf(&b, "  set %s { %d ranges, sha256 %x }\n", s.Name, len(s.Ranges), h.Sum(nil)[:8])
	}
	for _, c := range []Chain{ChainInput, ChainForward} {
		fmt.Fprintf(&b, "  chain %s {\n", c)
		for _, r := range rules {
			if r.Chain == c {
				fmt.Fprintf(&b, "    %s\n", r)
			}
		}
		b.WriteString("  }\n")
	}
	b.WriteString("}\n")
	return b.String()
}
