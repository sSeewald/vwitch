package config

import (
	"net/netip"
	"time"
)

// Defaults for new configurations and missing fields.
const (
	DefaultIngress     = "default"
	DefaultInterface   = "awg0"
	DefaultListenPort  = 51845
	DefaultMTU         = 1340
	DefaultPortalPort  = 80
	DefaultAdminListen = ":443"
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
	c.migrateIngress()
	setDefault(&s.MTU, DefaultMTU)
	if !s.Address.IsValid() {
		s.Address = DefaultAddress
	}
	if s.AdminInterfaces == nil {
		s.AdminInterfaces = []string{"lo", c.Ingresses[0].Interface} // localhost and every VPN client
	}
	for i := range c.Clients {
		setDefault(&c.Clients[i].Ingress, c.Ingresses[0].Name)
	}
	if !c.DNS.Resolver.IsValid() {
		c.DNS.Resolver = DefaultResolver
	}
	setDefault(&c.Selection.Strategy, StrategyFailover)
	setDefault(&c.Selection.Offline, OfflineBlock)
	c.Security.applyDefaults()

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

// migrateIngress moves the single ingress of older configs (server.interface,
// listen_port, awg) into the first ingress, so their clients keep working.
func (c *Config) migrateIngress() {
	s := &c.Server
	if len(c.Ingresses) == 0 {
		in := Ingress{Name: DefaultIngress, Interface: s.LegacyInterface, ListenPort: s.LegacyListenPort, AWG: s.LegacyAWG}
		setDefault(&in.Interface, DefaultInterface)
		setDefault(&in.ListenPort, DefaultListenPort)
		c.Ingresses = []Ingress{in}
	}
	s.LegacyInterface, s.LegacyListenPort, s.LegacyAWG = "", 0, AWGParams{}
}

func setDefault[T comparable](p *T, v T) {
	var zero T
	if *p == zero {
		*p = v
	}
}
