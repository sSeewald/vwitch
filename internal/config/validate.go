package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/sseewald/vwitch/internal/domains"
)

var (
	nameRE = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,31}$`)
	hostRE = regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)
)

// ValidateName checks a user supplied egress or client name.
func ValidateName(name string) error {
	if !nameRE.MatchString(name) {
		return fmt.Errorf("invalid name %q: use 1-32 chars of letters, digits, '_', '-', '.'", name)
	}
	return nil
}

// Validate checks the whole configuration and returns all problems found.
func (c *Config) Validate() error {
	var errs []error
	add := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }

	s := c.Server
	if !s.Address.Addr().Is4() {
		add("server.address must be an IPv4 prefix")
	}
	if s.Address.Bits() > 30 {
		add("server.address prefix too small")
	}
	if s.ListenPort == 0 {
		add("server.listen_port must be set")
	}
	if s.MTU < 1280 || s.MTU > 1500 {
		add("server.mtu must be between 1280 and 1500")
	}
	if s.PrivateKey == "" {
		add("server.private_key missing (run 'vwitch setup')")
	}
	if err := s.AWG.validate(); err != nil {
		add("server.awg: %w", err)
	}
	if !c.DNS.Resolver.Is4() {
		add("dns.resolver must be a public IPv4 address")
	} else if c.ClientNet().Contains(c.DNS.Resolver) || c.DNS.Resolver.IsPrivate() {
		add("dns.resolver must not be a LAN address, it would break on egress changes")
	}

	switch c.Selection.Strategy {
	case StrategyFailover, StrategyWeighted:
	case StrategyFixed:
		if _, ok := c.Egress(c.Selection.Fixed); !ok {
			add("selection.fixed: unknown egress %q", c.Selection.Fixed)
		}
	default:
		add("selection.strategy: unknown %q", c.Selection.Strategy)
	}
	switch c.Selection.Offline {
	case OfflineBlock:
	case OfflineAsk, OfflineDirect:
		if !s.AllowDirect {
			add("selection.offline %q requires server.allow_direct", c.Selection.Offline)
		}
	default:
		add("selection.offline: unknown %q", c.Selection.Offline)
	}

	h := c.Health
	if h.Interval <= 0 || h.Timeout <= 0 || h.Timeout >= h.Interval {
		add("health: need 0 < timeout < interval")
	}
	if h.Rise < 1 || h.Fall < 1 {
		add("health: rise and fall must be >= 1")
	}
	for _, t := range h.Targets {
		if err := t.validate(); err != nil {
			add("health.targets: %w", err)
		}
	}

	for _, a := range c.Web.Portal.Actions {
		switch a {
		case ActionFast, ActionDirect, ActionBlock:
			// fast/direct are hidden at runtime when server.allow_direct is off
		default:
			add("web.portal.actions: unknown %q", a)
		}
	}
	for _, h := range c.Web.Hostnames {
		if !hostRE.MatchString(h) {
			add("web.hostnames: invalid name %q", h)
		}
	}
	if !nameRE.MatchString(c.Web.Admin.Username) {
		add("web.admin.username %q: use letters, digits, '.', '_' or '-'", c.Web.Admin.Username)
	}
	if (c.Web.Admin.TLS.CertFile == "") != (c.Web.Admin.TLS.KeyFile == "") {
		add("web.admin.tls needs both cert_file and key_file")
	}

	seen := map[string]bool{}
	idx := map[int]bool{}
	for _, e := range c.Egresses {
		if err := ValidateName(e.Name); err != nil {
			add("egress: %w", err)
		}
		if seen["e:"+e.Name] {
			add("egress %q defined twice", e.Name)
		}
		seen["e:"+e.Name] = true
		if e.Index < 1 || e.Index > 999 || idx[e.Index] {
			add("egress %q: index must be unique in 1..999", e.Name)
		}
		idx[e.Index] = true
		if e.Weight < 1 {
			add("egress %q: weight must be >= 1", e.Name)
		}
		if _, _, err := SplitEndpoint(e.Endpoint); err != nil {
			add("egress %q: %w", e.Name, err)
		}
		switch e.Resolve {
		case ResolveAny, ResolveIPv4, ResolveIPv6:
		default:
			add("egress %q: resolve must be any, ipv4 or ipv6", e.Name)
		}
		if !e.Address.Is4() {
			add("egress %q: address must be IPv4", e.Name)
		}
		if e.PrivateKey == "" || e.PublicKey == "" {
			add("egress %q: keys missing", e.Name)
		}
		for _, t := range e.Targets {
			if err := t.validate(); err != nil {
				add("egress %q targets: %w", e.Name, err)
			}
		}
	}

	addrs := map[string]bool{c.ServerIP().String(): true}
	for _, cl := range c.Clients {
		if err := ValidateName(cl.Name); err != nil {
			add("client: %w", err)
		}
		if seen["c:"+cl.Name] {
			add("client %q defined twice", cl.Name)
		}
		seen["c:"+cl.Name] = true
		if !c.ClientNet().Contains(cl.Address) || addrs[cl.Address.String()] {
			add("client %q: address %s not unique in %s", cl.Name, cl.Address, c.ClientNet())
		}
		addrs[cl.Address.String()] = true
		if cl.PublicKey == "" {
			add("client %q: public key missing", cl.Name)
		}
		if len(cl.I) > 5 {
			add("client %q: at most 5 I-packets", cl.Name)
		}
		switch cl.Strategy {
		case "", StrategyFailover, StrategyWeighted:
		case StrategyFixed:
			if _, ok := c.Egress(cl.Fixed); !ok {
				add("client %q: unknown fixed egress %q", cl.Name, cl.Fixed)
			}
		default:
			add("client %q: unknown strategy %q", cl.Name, cl.Strategy)
		}
	}

	owner := map[string]string{} // domain -> route
	for _, r := range c.Routes {
		if err := ValidateName(r.Name); err != nil {
			add("route: %w", err)
		}
		if seen["r:"+r.Name] {
			add("route %q defined twice", r.Name)
		}
		seen["r:"+r.Name] = true
		if _, ok := c.Egress(r.Egress); !ok {
			add("route %q: unknown egress %q", r.Name, r.Egress)
		}
		if len(r.Domains) == 0 {
			add("route %q: no domains", r.Name)
		}
		if !slices.IsSorted(r.Domains) {
			add("route %q: domains must be sorted", r.Name)
		}
		for _, d := range r.Domains {
			if n, err := domains.Normalize(d); err != nil || n != d {
				add("route %q: invalid domain %q", r.Name, d)
				continue
			}
			if o, dup := owner[d]; dup {
				if o == r.Name {
					add("route %q: domain %s listed twice", r.Name, d)
				} else {
					add("route %q: domain %s is already in route %q", r.Name, d, o)
				}
				continue
			}
			owner[d] = r.Name
		}
	}
	return errors.Join(errs...)
}

func (p AWGParams) validate() error {
	switch {
	case p.Jc < 1 || p.Jc > 128:
		return errors.New("jc must be 1..128")
	case p.Jmin < 0 || p.Jmax <= p.Jmin || p.Jmax > 1280:
		return errors.New("need 0 <= jmin < jmax <= 1280")
	case p.S1+56 == p.S2:
		return errors.New("s1+56 must not equal s2")
	}
	type rng struct{ lo, hi uint32 }
	var rs []rng
	for i, h := range []string{p.H1, p.H2, p.H3, p.H4} {
		lo, hi, err := ParseRange(h)
		if err != nil {
			return fmt.Errorf("h%d: %w", i+1, err)
		}
		for _, r := range rs {
			if lo <= r.hi && r.lo <= hi {
				return fmt.Errorf("h%d overlaps another header range", i+1)
			}
		}
		rs = append(rs, rng{lo, hi})
	}
	if p.ContentPadding != "" {
		if _, hi, err := ParseRange(p.ContentPadding); err != nil || hi > MaxContentPadding {
			return fmt.Errorf("content_padding must be a range within 0-%d", MaxContentPadding)
		}
	}
	if p.HeaderProtectionKey != "" {
		if k, err := base64.StdEncoding.DecodeString(p.HeaderProtectionKey); err != nil || len(k) != 32 {
			return errors.New("header_protection_key must be a base64 32-byte key")
		}
		for i, sz := range []int{p.S1, p.S2, p.S3, p.S4} {
			if sz < MinHeaderProtectionPadding {
				return fmt.Errorf("header protection needs s%d >= %d", i+1, MinHeaderProtectionPadding)
			}
		}
	}
	return nil
}

// AWG 3.1 limits.
const (
	MaxContentPadding          = 1024
	MinHeaderProtectionPadding = 12 // the header cipher takes its nonce from the S1–S4 padding
)

func (t Target) validate() error {
	switch {
	case (t.Ping == "") == (t.URL == ""):
		return errors.New("target needs exactly one of ping or url")
	case t.Ping != "":
		if ip := net.ParseIP(t.Ping); ip == nil || ip.To4() == nil {
			return fmt.Errorf("ping %q is not an IPv4 address", t.Ping)
		}
	default:
		u, err := url.Parse(t.URL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("invalid url %q", t.URL)
		}
	}
	return nil
}

// ParseRange parses an AWG header range "lo-hi" (or a single value).
func ParseRange(s string) (lo, hi uint32, err error) {
	a, b, found := strings.Cut(s, "-")
	l, err := strconv.ParseUint(a, 10, 32)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid range %q", s)
	}
	h := l
	if found {
		if h, err = strconv.ParseUint(b, 10, 32); err != nil || h < l {
			return 0, 0, fmt.Errorf("invalid range %q", s)
		}
	}
	return uint32(l), uint32(h), nil
}

// SplitEndpoint splits "host:port" and "[v6]:port".
func SplitEndpoint(ep string) (host string, port uint16, err error) {
	h, p, err := net.SplitHostPort(ep)
	if err != nil || h == "" {
		return "", 0, fmt.Errorf("invalid endpoint %q", ep)
	}
	n, err := strconv.ParseUint(p, 10, 16)
	if err != nil || n == 0 {
		return "", 0, fmt.Errorf("invalid endpoint port in %q", ep)
	}
	return h, uint16(n), nil
}
