// Package domains holds the pure logic of domain routing: normalizing the
// domains an admin enters, matching DNS names against routes, and caching the
// addresses learned from DNS answers.
package domains

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"time"
)

var labelRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// Normalize turns user input like "https://www.Google.de/path", "*.google.de"
// or "google.de." into the canonical form "www.google.de" / "google.de".
// A domain always includes its subdomains.
func Normalize(s string) (string, error) {
	d := strings.ToLower(strings.TrimSpace(s))
	if i := strings.Index(d, "://"); i >= 0 {
		d = d[i+3:]
	}
	if i := strings.IndexAny(d, "/?#"); i >= 0 {
		d = d[:i]
	}
	if i := strings.LastIndex(d, ":"); i >= 0 { // port
		d = d[:i]
	}
	d = strings.TrimPrefix(d, "*.")
	d = strings.Trim(d, ".")
	if d == "" {
		return "", errors.New("empty domain")
	}
	if len(d) > 253 {
		return "", fmt.Errorf("domain %q too long", d)
	}
	for _, l := range strings.Split(d, ".") {
		if !labelRE.MatchString(l) {
			return "", fmt.Errorf("invalid domain %q", s)
		}
	}
	if _, err := netip.ParseAddr(d); err == nil {
		return "", fmt.Errorf("%q is an address, not a domain", s)
	}
	return d, nil
}

// Covers reports whether domain d matches name (d itself or a subdomain).
func Covers(d, name string) bool {
	return name == d || strings.HasSuffix(name, "."+d)
}

// Route is one routed domain list.
type Route struct {
	Name    string
	Domains []string // normalized
}

// Match returns the route whose domain matches name most specifically.
func Match(routes []Route, name string) (string, bool) {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	best, bestLen := "", -1
	for _, r := range routes {
		for _, d := range r.Domains {
			if len(d) > bestLen && Covers(d, name) {
				best, bestLen = r.Name, len(d)
			}
		}
	}
	return best, bestLen >= 0
}

// Cache remembers which addresses DNS answers returned for which route.
// Entries live at least MinTTL so long-lived connections keep their path
// after short DNS TTLs, and at most MaxTTL. Not safe for concurrent use.
type Cache struct {
	entries map[netip.Addr]entry
}

type entry struct {
	route   string
	expires time.Time
}

// Bounds for learned addresses.
const (
	MinTTL = time.Hour
	MaxTTL = 24 * time.Hour
)

// Learn stores addrs for route. It reports whether a new address (or one
// that moved to another route) appeared, i.e. whether routing must change.
func (c *Cache) Learn(route string, addrs []netip.Addr, ttl time.Duration, now time.Time) bool {
	if c.entries == nil {
		c.entries = map[netip.Addr]entry{}
	}
	ttl = min(max(ttl, MinTTL), MaxTTL)
	changed := false
	for _, a := range addrs {
		a = a.Unmap()
		if !a.Is4() {
			continue
		}
		old, ok := c.entries[a]
		if !ok || old.route != route || !old.expires.After(now) {
			changed = true
		}
		exp := now.Add(ttl)
		if ok && old.route == route && old.expires.After(exp) {
			exp = old.expires
		}
		c.entries[a] = entry{route: route, expires: exp}
	}
	return changed
}

// Active returns the unexpired addresses per route and drops expired ones.
func (c *Cache) Active(now time.Time) map[string][]netip.Addr {
	out := map[string][]netip.Addr{}
	for a, e := range c.entries {
		if !e.expires.After(now) {
			delete(c.entries, a)
			continue
		}
		out[e.route] = append(out[e.route], a)
	}
	return out
}

// Forget drops all addresses of routes not in keep.
func (c *Cache) Forget(keep func(route string) bool) {
	for a, e := range c.entries {
		if !keep(e.route) {
			delete(c.entries, a)
		}
	}
}
