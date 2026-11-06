package daemon

import (
	"slices"
	"time"

	"github.com/sseewald/vwitch/internal/clients"
	"github.com/sseewald/vwitch/internal/config"
	"github.com/sseewald/vwitch/internal/health"
	"github.com/sseewald/vwitch/internal/state"
	"github.com/sseewald/vwitch/internal/version"
)

// Status is a snapshot for CLI, admin UI and portal.
type Status struct {
	Version   string           `json:"version"` // daemon version
	Time      time.Time        `json:"time"`
	Selection config.Selection `json:"selection"`
	Switches  state.Switches   `json:"switches"`
	Ingresses []IngressStatus  `json:"ingresses"`
	Egresses  []EgressStatus   `json:"egresses"`
	Clients   []ClientStatus   `json:"clients"`
	Routes    []RouteStatus    `json:"routes,omitempty"`
	Events    []state.Event    `json:"events"`
}

// IngressStatus describes one ingress.
type IngressStatus struct {
	Name     string `json:"name"`
	Iface    string `json:"iface"`
	Port     uint16 `json:"port"`
	Strict   bool   `json:"strict"`   // header protection: AWG 3.1 clients only
	Isolated bool   `json:"isolated"` // no traffic between its clients and others
	Admin    bool   `json:"admin"`    // the admin UI is reachable through it
	Clients  int    `json:"clients"`
	Online   int    `json:"online"`
}

// EgressStatus describes one egress.
type EgressStatus struct {
	Name         string   `json:"name"`
	Iface        string   `json:"iface"`
	Enabled      bool     `json:"enabled"`
	Healthy      bool     `json:"healthy"`
	Priority     int      `json:"priority"`
	Weight       int      `json:"weight"`
	Tags         []string `json:"tags,omitempty"`
	Endpoint     string   `json:"endpoint"`
	Resolved     string   `json:"resolved,omitempty"`
	HandshakeAge float64  `json:"handshake_age"` // seconds, -1 never
	LatencyMs    float64  `json:"latency_ms"`
	RxBytes      int64    `json:"rx_bytes"`
	TxBytes      int64    `json:"tx_bytes"`
	RxRate       float64  `json:"rx_rate"` // bytes/s
	TxRate       float64  `json:"tx_rate"`
	Clients      int      `json:"clients"`
	Error        string   `json:"error,omitempty"`
}

// ClientStatus describes one client.
type ClientStatus struct {
	Name         string     `json:"name"`
	Address      string     `json:"address"`
	Enabled      bool       `json:"enabled"`
	Active       bool       `json:"active"`
	Expires      *time.Time `json:"expires,omitempty"`
	Online       bool       `json:"online"`
	HandshakeAge float64    `json:"handshake_age"`
	RxBytes      int64      `json:"rx_bytes"`
	TxBytes      int64      `json:"tx_bytes"`
	Exit         string     `json:"exit"` // "egress", "direct", "portal", "block", "" (inactive)
	Egress       string     `json:"egress,omitempty"`
	Reason       string     `json:"reason,omitempty"` // selector.Reason code
	Strategy     string     `json:"strategy,omitempty"`
	Fixed        string     `json:"fixed,omitempty"`
	Outdated     bool       `json:"outdated,omitempty"` // needs a new config (server settings changed)
	AWG3         bool       `json:"awg3,omitempty"`     // config carries the AWG 3.1 lines
	Ingress      string     `json:"ingress"`
	Strict       bool       `json:"strict,omitempty"` // its ingress uses header protection
	state.ClientSwitch
}

// onlineWindow: a client counts as online if it handshook recently.
const onlineWindow = 3 * time.Minute

func (d *Daemon) buildStatus(c *config.Config, sw state.Switches, now time.Time) Status {
	st := Status{Version: version.String(), Time: now, Selection: c.Selection, Switches: sw, Events: d.state.Events()}
	counts := map[string]int{}
	for _, t := range d.decisions {
		counts[t.Egress]++
	}
	for _, e := range c.SortedEgresses() {
		es := EgressStatus{Name: e.Name, Iface: e.Iface(), Enabled: e.Enabled, Priority: e.Priority, Weight: e.Weight,
			Tags: e.Tags, Endpoint: e.Endpoint, HandshakeAge: -1, Clients: counts[e.Name]}
		if rt, ok := d.egresses[e.Name]; ok {
			es.Healthy = e.Enabled && rt.tracker.Healthy()
			if rt.endpoint.IsValid() {
				es.Resolved = rt.endpoint.String()
			}
			if a := health.HandshakeAge(now, rt.stats.LastHandshake); a >= 0 {
				es.HandshakeAge = a.Seconds()
			}
			es.LatencyMs = float64(rt.latency.Microseconds()) / 1000
			es.RxBytes, es.TxBytes = rt.stats.RxBytes, rt.stats.TxBytes
			es.RxRate, es.TxRate = rt.rxRate, rt.txRate
			es.Error = rt.lastErr
		}
		st.Egresses = append(st.Egresses, es)
	}
	st.Routes = d.routeStatus(c, now)
	peers, _ := d.sys.PeerStats()
	for _, cl := range c.Clients {
		cs := ClientStatus{Name: cl.Name, Address: cl.Address.String(), Enabled: cl.Enabled, Active: cl.Active(now),
			Expires: cl.Expires, HandshakeAge: -1, Strategy: string(cl.Strategy), Fixed: cl.Fixed,
			Outdated: cl.Issued != "" && cl.Issued != clients.Fingerprint(c, cl), ClientSwitch: sw.Clients[cl.Name],
			Ingress: c.ClientIngress(cl).Name, Strict: c.ClientIngress(cl).AWG.Strict()}
		cs.AWG3 = cl.AWG3 || cs.Strict
		if p, ok := peers[cl.PublicKey]; ok {
			if a := health.HandshakeAge(now, p.LastHandshake); a >= 0 {
				cs.HandshakeAge = a.Seconds()
				cs.Online = a < onlineWindow
			}
			cs.RxBytes, cs.TxBytes = p.RxBytes, p.TxBytes
		}
		if t, ok := d.decisions[cl.Name]; ok {
			cs.Exit, cs.Egress, cs.Reason = string(t.Kind), t.Egress, string(t.Reason)
		}
		st.Clients = append(st.Clients, cs)
	}
	for _, in := range c.Ingresses {
		is := IngressStatus{Name: in.Name, Iface: in.Interface, Port: in.ListenPort, Strict: in.AWG.Strict(),
			Isolated: in.Isolated, Admin: slices.Contains(c.Server.AdminInterfaces, in.Interface)}
		for _, cs := range st.Clients {
			if cs.Ingress == in.Name {
				is.Clients++
				if cs.Online {
					is.Online++
				}
			}
		}
		st.Ingresses = append(st.Ingresses, is)
	}
	return st
}

// publish stores the snapshot and notifies subscribers. Caller holds d.mu.
func (d *Daemon) publish(st Status) {
	d.status = st
	for ch := range d.subs {
		select {
		case ch <- st:
		default: // slow subscriber, it will get the next one
		}
	}
}

// Status returns the latest snapshot.
func (d *Daemon) Status() Status {
	d.mu.Lock()
	defer d.mu.Unlock()
	st := d.status
	st.Egresses = slices.Clone(st.Egresses)
	st.Clients = slices.Clone(st.Clients)
	st.Routes = slices.Clone(st.Routes)
	st.Events = slices.Clone(st.Events)
	return st
}

// Subscribe returns a channel of status updates; call the cancel func when done.
func (d *Daemon) Subscribe() (<-chan Status, func()) {
	ch := make(chan Status, 1)
	d.mu.Lock()
	d.subs[ch] = struct{}{}
	d.mu.Unlock()
	return ch, func() {
		d.mu.Lock()
		delete(d.subs, ch)
		d.mu.Unlock()
	}
}

// ClientByAddr finds the client using a tunnel address (for the portal).
func (d *Daemon) ClientByAddr(addr string) (ClientStatus, bool) {
	st := d.Status()
	for _, c := range st.Clients {
		if c.Address == addr {
			return c, true
		}
	}
	return ClientStatus{}, false
}
