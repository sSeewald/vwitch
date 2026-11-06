// Package blocking holds the pure logic shared by all block sources: a
// domain matcher the DNS forwarder asks, the address filters the firewall
// applies, and the log every hit is recorded in. A source is anything that
// yields domains or address ranges (the admin's own list, countries, and
// later external lists); adding one never changes the consumers.
package blocking

import (
	"net/netip"
	"strings"

	"github.com/sseewald/vwitch/internal/iprange"
)

// Source names used in the log.
const (
	SourceCustom = "custom" // the admin's own domain list
	SourceRegion = "region" // country address ranges
)

// DomainSource is a named list of normalized domains.
type DomainSource struct {
	Name    string
	Domains []string
}

// Matcher answers whether a DNS name is blocked, by suffix: a listed
// domain covers all its subdomains. Lookups cost one map access per label,
// so large lists stay cheap. Not safe for concurrent mutation; build a new
// one instead.
type Matcher struct {
	domains map[string]string // domain -> source
}

// NewMatcher builds a matcher; earlier sources win on duplicates.
func NewMatcher(sources ...DomainSource) *Matcher {
	m := &Matcher{domains: map[string]string{}}
	for _, s := range sources {
		for _, d := range s.Domains {
			if _, ok := m.domains[d]; !ok {
				m.domains[d] = s.Name
			}
		}
	}
	return m
}

// Match returns the blocking source and domain for name, if any.
func (m *Matcher) Match(name string) (source, domain string, ok bool) {
	if m == nil || len(m.domains) == 0 {
		return "", "", false
	}
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	for {
		if s, hit := m.domains[name]; hit {
			return s, name, true
		}
		i := strings.IndexByte(name, '.')
		if i < 0 {
			return "", "", false
		}
		name = name[i+1:]
	}
}

// Len is the number of listed domains.
func (m *Matcher) Len() int {
	if m == nil {
		return 0
	}
	return len(m.domains)
}

// Filter is one address-based block rule for the firewall: connections in
// Direction to (outgoing) or from (incoming) the prefixes are dropped, or,
// with Allow, everything else is. Private, shared and link-local ranges are
// never filtered, so the LAN behind an egress and overlay networks keep
// working.
type Filter struct {
	Source   string
	Outgoing bool // client connections to these ranges
	Incoming bool // new connections from these ranges to the server
	Allow    bool
	Ranges   []iprange.Range
}

// Special are the ranges never filtered (always allowed).
var Special = func() []iprange.Range {
	var out []iprange.Range
	for _, p := range specialPrefixes {
		out = append(out, iprange.FromPrefix(p))
	}
	return out
}()

var specialPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("224.0.0.0/3"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
}
