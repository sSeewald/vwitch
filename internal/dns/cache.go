package dns

import (
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// cache keeps forwarded answers per question and egress, honoring their TTLs.
// The egress is part of the key because CDNs answer by the asking address.
type cache struct {
	mu      sync.Mutex
	entries map[cacheKey]cacheEntry
	now     func() time.Time
}

type cacheKey struct {
	name  string
	typ   dnsmessage.Type
	iface string
}

type cacheEntry struct {
	msg     dnsmessage.Message
	stored  time.Time
	expires time.Time
}

const (
	cacheMax         = 10000
	cacheMaxTTL      = time.Hour
	cacheNegativeTTL = time.Minute // NXDOMAIN / NODATA without a usable SOA
)

func newCache() *cache {
	return &cache{entries: map[cacheKey]cacheEntry{}, now: time.Now}
}

func cacheKeyOf(q dnsmessage.Question, iface string) cacheKey {
	return cacheKey{name: strings.ToLower(q.Name.String()), typ: q.Type, iface: iface}
}

// put stores a successful or negative answer. Truncated and failed answers
// are not cached.
func (c *cache) put(k cacheKey, resp []byte) {
	var m dnsmessage.Message
	if m.Unpack(resp) != nil || m.Truncated {
		return
	}
	if m.RCode != dnsmessage.RCodeSuccess && m.RCode != dnsmessage.RCodeNameError {
		return
	}
	ttl := cacheTTL(m)
	if ttl <= 0 {
		return
	}
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) >= cacheMax {
		c.prune(now)
	}
	c.entries[k] = cacheEntry{msg: m, stored: now, expires: now.Add(ttl)}
}

// get returns the cached answer for query id with TTLs counted down, or nil.
func (c *cache) get(k cacheKey, id uint16) []byte {
	now := c.now()
	c.mu.Lock()
	e, ok := c.entries[k]
	if ok && !e.expires.After(now) {
		delete(c.entries, k)
		ok = false
	}
	c.mu.Unlock()
	if !ok {
		return nil
	}
	m := e.msg // the resource slices are shared: copy before changing TTLs
	m.ID = id
	age := uint32(now.Sub(e.stored) / time.Second)
	m.Answers = aged(m.Answers, age)
	m.Authorities = aged(m.Authorities, age)
	m.Additionals = aged(m.Additionals, age)
	out, err := m.Pack()
	if err != nil {
		return nil
	}
	return out
}

func aged(rs []dnsmessage.Resource, age uint32) []dnsmessage.Resource {
	out := make([]dnsmessage.Resource, len(rs))
	for i, r := range rs {
		if r.Header.Type != dnsmessage.TypeOPT {
			r.Header.TTL -= min(age, r.Header.TTL)
		}
		out[i] = r
	}
	return out
}

// cacheTTL is the lowest TTL of the answer, or for negative answers the SOA
// minimum (RFC 2308), capped to cacheMaxTTL.
func cacheTTL(m dnsmessage.Message) time.Duration {
	lowest := uint32(0)
	seen := false
	for _, r := range m.Answers {
		if !seen || r.Header.TTL < lowest {
			lowest, seen = r.Header.TTL, true
		}
	}
	if !seen {
		for _, r := range m.Authorities {
			if soa, ok := r.Body.(*dnsmessage.SOAResource); ok {
				return min(time.Duration(min(r.Header.TTL, soa.MinTTL))*time.Second, cacheMaxTTL)
			}
		}
		return cacheNegativeTTL
	}
	return min(time.Duration(lowest)*time.Second, cacheMaxTTL)
}

// prune drops expired entries, and half of the rest if still full.
// Caller holds c.mu.
func (c *cache) prune(now time.Time) {
	for k, e := range c.entries {
		if !e.expires.After(now) {
			delete(c.entries, k)
		}
	}
	for k := range c.entries {
		if len(c.entries) < cacheMax/2 {
			break
		}
		delete(c.entries, k)
	}
}

// udpLimit is the largest UDP answer the query allows (EDNS0, else 512).
func udpLimit(q []byte) int {
	var m dnsmessage.Message
	if m.Unpack(q) != nil {
		return 512
	}
	for _, r := range m.Additionals {
		if r.Header.Type == dnsmessage.TypeOPT {
			return max(512, int(r.Header.Class)) // OPT carries the size in Class
		}
	}
	return 512
}
