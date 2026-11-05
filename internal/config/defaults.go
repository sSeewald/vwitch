package config

import (
	"net/netip"
	"time"
)

// Defaults for new configurations and missing fields.
const (
	DefaultInterface   = "awg0"
	DefaultListenPort  = 51845
	DefaultMTU         = 1340
	DefaultPortalPort  = 80
	DefaultAdminListen = ":8090"
	DefaultAdminUser   = "admin"
	DefaultKeepalive   = 25
	DefaultWeight      = 1
	DefaultHostname    = "v.witch"
	DefaultLanguage    = "en"
)

var (
	DefaultAddress  = netip.MustParsePrefix("10.8.0.1/24")
	DefaultResolver = netip.MustParseAddr("9.9.9.9")
)

// New returns a configuration with all defaults applied. Keys and AWG
// parameters are left empty; package setup generates them.
func New() *Config {
	c := &Config{}
	c.ApplyDefaults()
	return c
}

// ApplyDefaults fills zero values with defaults. It never overwrites
// explicitly set values.
func (c *Config) ApplyDefaults() {
	s := &c.Server
	setDefault(&s.Interface, DefaultInterface)
	setDefault(&s.ListenPort, DefaultListenPort)
	setDefault(&s.MTU, DefaultMTU)
	if !s.Address.IsValid() {
		s.Address = DefaultAddress
	}
	if s.AdminInterfaces == nil {
		s.AdminInterfaces = []string{"lo"}
	}
	if !c.DNS.Resolver.IsValid() {
		c.DNS.Resolver = DefaultResolver
	}
	setDefault(&c.Selection.Strategy, StrategyFailover)
	setDefault(&c.Selection.Offline, OfflineBlock)

	h := &c.Health
	setDefault(&h.Interval, 10*time.Second)
	setDefault(&h.Timeout, 3*time.Second)
	setDefault(&h.HandshakeMaxAge, 200*time.Second)
	setDefault(&h.ReresolveAfter, 150*time.Second)
	setDefault(&h.Rise, 2)
	setDefault(&h.Fall, 3)
	if h.Targets == nil {
		h.Targets = []Target{
			{Ping: "1.1.1.1"},
			{URL: "http://connectivitycheck.gstatic.com/generate_204"},
		}
	}

	if c.Web.Hostnames == nil {
		c.Web.Hostnames = []string{DefaultHostname, "vwitch.internal"}
	}
	setDefault(&c.Web.Language, DefaultLanguage)
	setDefault(&c.Web.Portal.Port, DefaultPortalPort)
	if c.Web.Portal.Actions == nil {
		c.Web.Portal.Actions = []PortalAction{ActionFast, ActionDirect}
	}
	setDefault(&c.Web.Admin.Listen, DefaultAdminListen)
	setDefault(&c.Web.Admin.Username, DefaultAdminUser)

	for i := range c.Egresses {
		e := &c.Egresses[i]
		setDefault(&e.Resolve, ResolveAny)
		setDefault(&e.Weight, DefaultWeight)
		setDefault(&e.Keepalive, DefaultKeepalive)
	}
}

func setDefault[T comparable](p *T, v T) {
	var zero T
	if *p == zero {
		*p = v
	}
}
