package config

import (
	"regexp"
	"slices"

	"github.com/sseewald/vwitch/internal/domains"
)

// Security configures blocking. Every list or region selection is a source
// that the DNS forwarder (domains) or the firewall (address ranges) applies;
// each hit is recorded in the block log.
type Security struct {
	// BlockedDomains are answered with 0.0.0.0 / :: (subdomains included).
	BlockedDomains []string `yaml:"blocked_domains,omitempty"`
	Regions        Regions  `yaml:"regions,omitempty"`
	// NoActivity switches off the in-memory list of looked-up domains.
	NoActivity bool `yaml:"no_activity,omitempty"`
}

// RegionMode decides whether the listed countries are blocked or the only
// ones allowed.
type RegionMode string

const (
	RegionBlock RegionMode = "block"
	RegionAllow RegionMode = "allow"
)

// Direction selects which connections a region filter applies to:
// outgoing ones started by clients, incoming ones to the server, or both.
type Direction string

const (
	DirectionBoth     Direction = "both"
	DirectionOutgoing Direction = "outgoing"
	DirectionIncoming Direction = "incoming"
)

// Regions blocks or allows countries by their registered address ranges.
type Regions struct {
	Enabled   bool       `yaml:"enabled,omitempty"`
	Mode      RegionMode `yaml:"mode,omitempty"`
	Direction Direction  `yaml:"direction,omitempty"`
	Countries []string   `yaml:"countries,omitempty"` // ISO 3166-1 alpha-2, upper case
}

// Active reports whether region filtering applies at all.
func (r Regions) Active() bool { return r.Enabled && len(r.Countries) > 0 }

// Outgoing and Incoming report the directions the filter applies to.
func (r Regions) Outgoing() bool { return r.Active() && r.Direction != DirectionIncoming }
func (r Regions) Incoming() bool { return r.Active() && r.Direction != DirectionOutgoing }

func (s *Security) applyDefaults() {
	setDefault(&s.Regions.Mode, RegionBlock)
	setDefault(&s.Regions.Direction, DirectionBoth)
}

var countryRE = regexp.MustCompile(`^[A-Z]{2}$`)

func (s Security) validate(add func(string, ...any)) {
	seen := map[string]bool{}
	for _, d := range s.BlockedDomains {
		n, err := domains.Normalize(d)
		switch {
		case err != nil:
			add("security.blocked_domains: %v", err)
		case n != d:
			add("security.blocked_domains: %q must be written as %q", d, n)
		case seen[n]:
			add("security.blocked_domains: %s listed twice", n)
		}
		seen[n] = true
	}
	if !slices.IsSorted(s.BlockedDomains) {
		add("security.blocked_domains must be sorted")
	}
	r := s.Regions
	switch r.Mode {
	case RegionBlock, RegionAllow:
	default:
		add("security.regions.mode must be block or allow")
	}
	switch r.Direction {
	case DirectionBoth, DirectionOutgoing, DirectionIncoming:
	default:
		add("security.regions.direction must be both, outgoing or incoming")
	}
	cs := map[string]bool{}
	for _, c := range r.Countries {
		if !countryRE.MatchString(c) {
			add("security.regions.countries: %q is not a two-letter country code", c)
		}
		if cs[c] {
			add("security.regions.countries: %s listed twice", c)
		}
		cs[c] = true
	}
	if r.Enabled && r.Mode == RegionAllow && len(r.Countries) == 0 {
		add("security.regions: allow mode needs at least one country, it would block everything")
	}
}
