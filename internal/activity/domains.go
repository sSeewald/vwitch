// Package activity keeps what the admin sees about client usage: the
// domains clients look up and their traffic over time. Everything is pure
// and in memory; the daemon feeds it and persists the traffic history.
package activity

import (
	"cmp"
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
	Names   []string  `json:"names"` // recent full names, newest first
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
	clients map[string]*count
	last    time.Time
	names   []string
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
