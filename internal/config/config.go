// Package config defines the declarative vwitch configuration (vwitch.yaml),
// its defaults and validation. It is the single source of truth for desired
// state; runtime state lives in package state.
package config

import (
	"net/netip"
	"slices"
	"strconv"
	"time"
)

// Default file locations.
const (
	DefaultPath     = "/etc/vwitch/vwitch.yaml"
	DefaultStateDir = "/var/lib/vwitch"
	DefaultSocket   = "/run/vwitch/api.sock"
)

// Strategy selects how a client is mapped to an egress.
type Strategy string

const (
	StrategyFailover Strategy = "failover"
	StrategyWeighted Strategy = "weighted"
	StrategyFixed    Strategy = "fixed"
)

// OfflinePolicy decides what happens when no egress is available.
type OfflinePolicy string

const (
	OfflineBlock  OfflinePolicy = "block"
	OfflineAsk    OfflinePolicy = "ask"
	OfflineDirect OfflinePolicy = "direct"
)

// ResolveFamily restricts endpoint hostname resolution.
type ResolveFamily string

const (
	ResolveAny  ResolveFamily = "any"
	ResolveIPv4 ResolveFamily = "ipv4"
	ResolveIPv6 ResolveFamily = "ipv6"
)

// PortalAction is a switch a client may use on its status page.
type PortalAction string

const (
	ActionFast   PortalAction = "fast"   // force direct exit for this client
	ActionDirect PortalAction = "direct" // confirm direct exit while offline (policy ask)
	ActionBlock  PortalAction = "block"  // client's own kill switch
)

// Config is the root of vwitch.yaml.
type Config struct {
	Server    Server    `yaml:"server"`
	Ingresses []Ingress `yaml:"ingresses"`
	DNS       DNS       `yaml:"dns"`
	Selection Selection `yaml:"selection"`
	Health    Health    `yaml:"health"`
	Web       Web       `yaml:"web"`
	Egresses  []Egress  `yaml:"egresses"`
	Clients   []Client  `yaml:"clients"`
	Routes    []Route   `yaml:"routes,omitempty"`
	Security  Security  `yaml:"security,omitempty"`
}

// Server holds what all ingresses share: endpoint, client network, MTU and
// the server key.
type Server struct {
	// Endpoint is the public host or IP clients connect to.
	Endpoint   string       `yaml:"endpoint"`
	Address    netip.Prefix `yaml:"address"` // server IP + client network, e.g. 10.8.0.1/24
	MTU        int          `yaml:"mtu"`
	PrivateKey string       `yaml:"private_key"`
	// The single ingress of configs before ingresses existed. It is moved to
	// the first ingress when the config is loaded and never written again.
	LegacyInterface  string    `yaml:"interface,omitempty"`
	LegacyListenPort uint16    `yaml:"listen_port,omitempty"`
	LegacyAWG        AWGParams `yaml:"awg,omitempty"`
	// AllowDirect permits the VPS's own uplink as exit (fast switch, offline policy direct/ask).
	AllowDirect bool `yaml:"allow_direct"`
	// AdminInterfaces may reach the admin UI and, with LockdownSSH, SSH.
	AdminInterfaces []string `yaml:"admin_interfaces"`
	// LockdownSSH drops SSH on all other interfaces once an admin interface (e.g. wt0) is up.
	LockdownSSH bool `yaml:"lockdown_ssh"`
}

// AWGParams are the AmneziaWG obfuscation parameters shared by server and clients.
type AWGParams struct {
	Jc   int    `yaml:"jc"`
	Jmin int    `yaml:"jmin"`
	Jmax int    `yaml:"jmax"`
	S1   int    `yaml:"s1"`
	S2   int    `yaml:"s2"`
	S3   int    `yaml:"s3"`
	S4   int    `yaml:"s4"`
	H1   string `yaml:"h1"` // range "lo-hi"
	H2   string `yaml:"h2"`
	H3   string `yaml:"h3"`
	H4   string `yaml:"h4"`

	// AmneziaWG 3.1. Without a header protection key, clients without
	// AWG 3.1 support keep working.
	DisableCookies bool   `yaml:"disable_cookies,omitempty"` // never send cookie replies (server only)
	ContentPadding string `yaml:"content_padding,omitempty"` // random padding range "lo-hi" for transport data
	// HeaderProtectionKey (base64) encrypts the packet headers. Every client
	// must know it, so clients without AWG 3.1 can no longer connect.
	HeaderProtectionKey string `yaml:"header_protection_key,omitempty"`
	RandomTrailers      bool   `yaml:"random_trailers,omitempty"` // random bytes after each packet; needs AWG 3.1 on both sides
	// NewClientsAWG3 is the default of Client.AWG3 for new clients.
	NewClientsAWG3 bool `yaml:"new_clients_awg3,omitempty"`
}

// Strict reports whether only AWG 3.1 clients can connect.
func (p AWGParams) Strict() bool { return p.HeaderProtectionKey != "" || p.RandomTrailers }

// DNS configures the resolver forced on clients.
type DNS struct {
	Resolver netip.Addr `yaml:"resolver"`
}

// Selection is the global egress selection policy.
type Selection struct {
	Strategy Strategy      `yaml:"strategy"`
	Fixed    string        `yaml:"fixed,omitempty"`
	Offline  OfflinePolicy `yaml:"offline"`
}

// Health configures egress health checks.
type Health struct {
	Interval        time.Duration `yaml:"interval"`
	Timeout         time.Duration `yaml:"timeout"`
	HandshakeMaxAge time.Duration `yaml:"handshake_max_age"`
	ReresolveAfter  time.Duration `yaml:"reresolve_after"`
	Rise            int           `yaml:"rise"`
	Fall            int           `yaml:"fall"`
	Targets         []Target      `yaml:"targets"`
}

// Target is one active probe. Exactly one of Ping or URL is set.
type Target struct {
	Ping string `yaml:"ping,omitempty"` // IPv4 address for ICMP echo
	URL  string `yaml:"url,omitempty"`  // HTTP(S) URL, any 2xx/3xx counts as up
}

// Web configures the client portal and the admin UI.
type Web struct {
	// Hostnames are answered by vwitch's DNS with the server IP; the first
	// one is used in links. Default: v.witch, plus vwitch.internal (reserved for private use).
	Hostnames []string `yaml:"hostnames"`
	// Language is the fallback UI language when the browser sends none we know.
	Language string `yaml:"language"`
	Portal   Portal `yaml:"portal"`
	Admin    Admin  `yaml:"admin"`
}

// Portal is the client status page, reachable only via the ingress interface.
type Portal struct {
	Port    uint16         `yaml:"port"`
	Actions []PortalAction `yaml:"actions"`
}

// Admin is the password protected admin UI.
type Admin struct {
	Listen       string `yaml:"listen"`
	Username     string `yaml:"username"` // login name; password managers need one
	PasswordHash string `yaml:"password_hash"`
	TLS          TLS    `yaml:"tls,omitempty"`
}

// TLS optionally serves the admin UI over HTTPS.
type TLS struct {
	CertFile string `yaml:"cert_file,omitempty"`
	KeyFile  string `yaml:"key_file,omitempty"`
}

// Enabled reports whether a certificate is configured.
func (t TLS) Enabled() bool { return t.CertFile != "" && t.KeyFile != "" }

// Egress is a WireGuard peer the VPS connects to as client.
type Egress struct {
	Name     string   `yaml:"name"`
	Index    int      `yaml:"index"` // stable, derives interface name and routing table
	Enabled  bool     `yaml:"enabled"`
	Priority int      `yaml:"priority"` // lower is preferred (failover order)
	Weight   int      `yaml:"weight"`
	Tags     []string `yaml:"tags,omitempty"`

	Endpoint     string        `yaml:"endpoint"` // host:port, host may be a name
	Resolve      ResolveFamily `yaml:"resolve"`
	Address      netip.Addr    `yaml:"address"` // our tunnel address on the peer's side
	PrivateKey   string        `yaml:"private_key"`
	PublicKey    string        `yaml:"public_key"`
	PresharedKey string        `yaml:"preshared_key,omitempty"`
	MTU          int           `yaml:"mtu,omitempty"`
	Keepalive    int           `yaml:"keepalive"`

	// Optional per-egress health overrides.
	HandshakeMaxAge time.Duration `yaml:"handshake_max_age,omitempty"`
	Targets         []Target      `yaml:"targets,omitempty"`
}

// Ingress is one AmneziaWG entry point: its own interface, UDP port and
// camouflage parameters. All ingresses share the client network, the server
// address and the server key; each client connects through one of them.
type Ingress struct {
	Name       string    `yaml:"name"`
	Interface  string    `yaml:"interface"`
	ListenPort uint16    `yaml:"listen_port"`
	AWG        AWGParams `yaml:"awg"`
	// Isolated clients reach their egress, DNS and the portal, but no other
	// client, and no other client reaches them.
	Isolated bool `yaml:"isolated,omitempty"`
}

// IngressIfacePrefix starts every ingress interface name (awg0, awg1, ...).
const IngressIfacePrefix = "awg"

// Client is an AmneziaWG peer connecting to the server.
type Client struct {
	Name         string     `yaml:"name"`
	Enabled      bool       `yaml:"enabled"`
	Ingress      string     `yaml:"ingress"` // the ingress the client connects through
	Address      netip.Addr `yaml:"address"`
	PublicKey    string     `yaml:"public_key"`       // the private key is shown once and never stored
	Issued       string     `yaml:"issued,omitempty"` // fingerprint of the config the client received
	PresharedKey string     `yaml:"preshared_key"`
	Expires      *time.Time `yaml:"expires,omitempty"`
	// Optional overrides of the global selection.
	Strategy Strategy `yaml:"strategy,omitempty"`
	Fixed    string   `yaml:"fixed,omitempty"`
	// Optional AWG 2.0 I1–I5 packets; some clients do not support them.
	I []string `yaml:"i,omitempty"`
	// AWG3 adds the AWG 3.1 lines to the client config. Clients without
	// AWG 3.1 support reject unknown lines, so this is opt-in per client.
	AWG3 bool `yaml:"awg3,omitempty"`
}

// Active reports whether the client may connect at time now.
func (c Client) Active(now time.Time) bool {
	return c.Enabled && (c.Expires == nil || now.Before(*c.Expires))
}

// Naming of kernel objects derived from the egress index.
const (
	EgressIfacePrefix = "vwe"
	EgressTableBase   = 51820
)

// Iface returns the egress interface name.
func (e Egress) Iface() string { return EgressIfacePrefix + strconv.Itoa(e.Index) }

// Table returns the egress routing table id.
func (e Egress) Table() int { return EgressTableBase + e.Index }

// EffectiveMaxAge returns the handshake limit for this egress.
func (e Egress) EffectiveMaxAge(h Health) time.Duration {
	if e.HandshakeMaxAge > 0 {
		return e.HandshakeMaxAge
	}
	return h.HandshakeMaxAge
}

// EffectiveTargets returns the probe targets for this egress.
func (e Egress) EffectiveTargets(h Health) []Target {
	if len(e.Targets) > 0 {
		return e.Targets
	}
	return h.Targets
}

// ServerIP is the server's address inside the client network.
func (c *Config) ServerIP() netip.Addr { return c.Server.Address.Addr() }

// ClientNet is the client network prefix.
func (c *Config) ClientNet() netip.Prefix { return c.Server.Address.Masked() }

// Ingress returns the ingress with the given name.
func (c *Config) Ingress(name string) (*Ingress, bool) {
	for i := range c.Ingresses {
		if c.Ingresses[i].Name == name {
			return &c.Ingresses[i], true
		}
	}
	return nil, false
}

// ClientIngress returns the ingress a client connects through (the first
// one if its ingress is unknown, which validation rejects).
func (c *Config) ClientIngress(cl Client) *Ingress {
	if in, ok := c.Ingress(cl.Ingress); ok {
		return in
	}
	return &c.Ingresses[0]
}

// IngressIfaces returns the interface names of all ingresses.
func (c *Config) IngressIfaces() []string {
	out := make([]string, len(c.Ingresses))
	for i, in := range c.Ingresses {
		out[i] = in.Interface
	}
	return out
}

// NextIngressIface returns the lowest unused ingress interface name.
func (c *Config) NextIngressIface() string {
	for n := 0; ; n++ {
		name := IngressIfacePrefix + strconv.Itoa(n)
		if !slices.Contains(c.IngressIfaces(), name) {
			return name
		}
	}
}

// Egress returns the egress with the given name.
func (c *Config) Egress(name string) (*Egress, bool) {
	for i := range c.Egresses {
		if c.Egresses[i].Name == name {
			return &c.Egresses[i], true
		}
	}
	return nil, false
}

// Client returns the client with the given name.
// Route sends the listed domains, including their subdomains, through one
// egress. Domains are normalized (domains.Normalize), sorted and unique
// across all routes.
type Route struct {
	Name    string   `yaml:"name"`
	Egress  string   `yaml:"egress"`
	Domains []string `yaml:"domains"`
}

// Route returns the route with the given name.
func (c *Config) Route(name string) (*Route, bool) {
	for i := range c.Routes {
		if c.Routes[i].Name == name {
			return &c.Routes[i], true
		}
	}
	return nil, false
}

func (c *Config) Client(name string) (*Client, bool) {
	for i := range c.Clients {
		if c.Clients[i].Name == name {
			return &c.Clients[i], true
		}
	}
	return nil, false
}
