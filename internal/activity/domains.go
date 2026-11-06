// Package activity keeps what the admin sees about client usage: the
// domains clients look up and their traffic over time. Everything is pure
// and in memory; the daemon feeds it and persists the traffic history.
package activity

import (
	"cmp"
	"net/netip"
	"slices"
	"sync"
	"time"

	"golang.org/x/net/publicsuffix"
)

// DomainStat summarizes one registrable domain (e.g. googlevideo.com for
// rr3.sn-4g5e.googlevideo.com).
type DomainStat struct {
	Domain  string    `json:"domain"`
	Queries int       `json:"queries"`
	Blocked int       `json:"blocked"`
	Clients []string  `json:"clients"`
	Last    time.Time `json:"last"`
	Names   []string  `json:"names"`             // recent full names, newest first
	Country string    `json:"country,omitempty"` // a country filter rejected its address
}

// Domains aggregates DNS lookups per registrable domain. Entries older than
// keep are dropped, and at most max are kept (the least recent go first).
type Domains struct {
	mu      sync.Mutex
	keep    time.Duration
	max     int
	entries map[string]*domainEntry
}

type domainEntry struct {
	clients   map[string]*count
	last      time.Time
	names     []string
	country   string // last country filter hit, see RegionBlocked
	countryAt time.Time
}

type count struct{ queries, blocked int }

const maxNames = 5

// NewDomains creates an aggregator.
func NewDomains(keep time.Duration, max int) *Domains {
	return &Domains{keep: keep, max: max, entries: map[string]*domainEntry{}}
}

// Base returns the registrable domain of name, or name itself.
func Base(name string) string {
	if b, err := publicsuffix.EffectiveTLDPlusOne(name); err == nil {
		return b
	}
	return name
}

// Seen records one lookup of name by client.
func (d *Domains) Seen(client, name string, blocked bool, now time.Time) {
	base := Base(name)
	d.mu.Lock()
	defer d.mu.Unlock()
	e, ok := d.entries[base]
	if !ok {
		if len(d.entries) >= d.max {
			d.evict(now)
		}
		e = &domainEntry{clients: map[string]*count{}}
		d.entries[base] = e
	}
	c, ok := e.clients[client]
	if !ok {
		c = &count{}
		e.clients[client] = c
	}
	c.queries++
	if blocked {
		c.blocked++
	}
	e.last = now
	if i := slices.Index(e.names, name); i >= 0 {
		e.names = slices.Delete(e.names, i, i+1)
	}
	e.names = slices.Insert(e.names, 0, name)
	if len(e.names) > maxNames {
		e.names = e.names[:maxNames]
	}
}

// evict drops expired entries, or the least recent one. Caller holds d.mu.
func (d *Domains) evict(now time.Time) {
	oldest, at := "", now
	for k, e := range d.entries {
		if now.Sub(e.last) > d.keep {
			delete(d.entries, k)
			continue
		}
		if e.last.Before(at) || oldest == "" {
			oldest, at = k, e.last
		}
	}
	if len(d.entries) >= d.max {
		delete(d.entries, oldest)
	}
}

// List returns the domains of the last keep period, most queried first.
// With client set, only that client's lookups count.
func (d *Domains) List(client string, now time.Time) []DomainStat {
	d.mu.Lock()
	defer d.mu.Unlock()
	var out []DomainStat
	for k, e := range d.entries {
		if now.Sub(e.last) > d.keep {
			delete(d.entries, k)
			continue
		}
		s := DomainStat{Domain: k, Last: e.last, Names: slices.Clone(e.names)}
		if now.Sub(e.countryAt) <= d.keep {
			s.Country = e.country
		}
		for name, c := range e.clients {
			if client != "" && name != client {
				continue
			}
			s.Queries += c.queries
			s.Blocked += c.blocked
			s.Clients = append(s.Clients, name)
		}
		if s.Queries == 0 {
			continue
		}
		slices.Sort(s.Clients)
		out = append(out, s)
	}
	slices.SortFunc(out, func(a, b DomainStat) int {
		return cmp.Or(cmp.Compare(b.Queries, a.Queries), cmp.Compare(a.Domain, b.Domain))
	})
	return out
}

// Clear forgets everything (activity list switched off).
func (d *Domains) Clear() {
	d.mu.Lock()
	defer d.mu.Unlock()
	clear(d.entries)
}

// RegionBlocked marks a domain whose address a country filter rejected for
// a client; the domain list then shows it as blocked with the country.
func (d *Domains) RegionBlocked(name, country string, now time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if e, ok := d.entries[Base(name)]; ok {
		e.country, e.countryAt = country, now
	}
}

// Resolved remembers which name the DNS answers of the last keep period
// gave for an address, so a connection to that address can be named.
type Resolved struct {
	mu   sync.Mutex
	keep time.Duration
	max  int
	m    map[netip.Addr]resolved
}

type resolved struct {
	name string
	at   time.Time
}

// NewResolved creates an address to name memory.
func NewResolved(keep time.Duration, max int) *Resolved {
	return &Resolved{keep: keep, max: max, m: map[netip.Addr]resolved{}}
}

// Add records the addresses of one answer for name.
func (r *Resolved) Add(name string, addrs []netip.Addr, now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.m)+len(addrs) > r.max {
		for a, v := range r.m {
			if now.Sub(v.at) > r.keep {
				delete(r.m, a)
			}
		}
		if len(r.m)+len(addrs) > r.max {
			clear(r.m) // rare: more distinct answers than max within keep
		}
	}
	for _, a := range addrs {
		r.m[a] = resolved{name, now}
	}
}

// Name returns the name last resolved to a, or "".
func (r *Resolved) Name(a netip.Addr, now time.Time) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if v, ok := r.m[a]; ok && now.Sub(v.at) <= r.keep {
		return v.name
	}
	return ""
}
