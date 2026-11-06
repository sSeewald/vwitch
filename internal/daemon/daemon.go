// Package daemon runs vwitch: it reconciles desired configuration and
// runtime switches with the host and offers the operations used by the CLI
// (via package api) and the admin UI.
package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/sseewald/vwitch/internal/config"
	"github.com/sseewald/vwitch/internal/dns"
	"github.com/sseewald/vwitch/internal/domains"
	"github.com/sseewald/vwitch/internal/egress"
	"github.com/sseewald/vwitch/internal/firewall"
	"github.com/sseewald/vwitch/internal/health"
	"github.com/sseewald/vwitch/internal/i18n"
	"github.com/sseewald/vwitch/internal/ingress"
	"github.com/sseewald/vwitch/internal/routing"
	"github.com/sseewald/vwitch/internal/selector"
	"github.com/sseewald/vwitch/internal/state"
)

// Daemon owns the reconcile loop.
type Daemon struct {
	cfg   *config.Store
	state *state.Store
	sys   System
	log   *slog.Logger
	res   dns.Resolver
	now   func() time.Time

	trigger chan struct{}

	mu        sync.Mutex // guards everything below
	egresses  map[string]*egressRuntime
	decisions map[string]selector.Target // by client name
	lastFW    string
	basePlan  routing.Plan            // routing without domain rules, from the last reconcile
	learned   domains.Cache           // addresses learned for domain routes
	ingSpecs  map[string]ingress.Spec // applied, by interface
	prot      protection
	status    Status
	subs      map[chan Status]struct{}
}

type egressRuntime struct {
	tracker   health.Tracker
	endpoint  netip.AddrPort
	resolved  time.Time
	latency   time.Duration
	lastErr   string
	stats     egress.Stats
	prevStats egress.Stats
	prevAt    time.Time
	rxRate    float64
	txRate    float64
}

// New creates a daemon. sys may be nil only in tests that never run it.
func New(cfg *config.Store, st *state.Store, sys System, log *slog.Logger) *Daemon {
	return &Daemon{
		cfg: cfg, state: st, sys: sys, log: log, now: time.Now,
		trigger:   make(chan struct{}, 1),
		egresses:  map[string]*egressRuntime{},
		decisions: map[string]selector.Target{},
		subs:      map[chan Status]struct{}{},
		ingSpecs:  map[string]ingress.Spec{},
		prot:      newProtection(),
	}
}

// Run prepares the host and reconciles until ctx ends.
func (d *Daemon) Run(ctx context.Context) error {
	if err := d.sys.Prepare(); err != nil {
		return err
	}
	c := d.cfg.Get()
	for _, sp := range ingress.Specs(c) {
		if err := d.sys.IngressUp(sp); err != nil {
			return fmt.Errorf("ingress %s: %w", sp.Name, err)
		}
		d.ingSpecs[sp.Name] = sp
	}
	// Fail-safe first: firewall and the unreachable rule before any peer connects.
	d.reconcile(ctx)

	fwd := &dns.Forwarder{
		Listen:   c.ServerIP(),
		Upstream: netip.AddrPortFrom(c.DNS.Resolver, 53),
		Names:    func() []string { return d.cfg.Get().Web.Hostnames },
		Protect:  c.Server.Address.Masked(),
		Route:    d.dnsRoute,
		Learn:    d.learn,
		Block:    d.dnsBlock,
		Seen:     d.dnsSeen,
		Timeout:  c.Health.Timeout,
		Log:      d.log,
	}
	go d.runProtection(ctx)
	go func() {
		if err := fwd.Serve(ctx); err != nil {
			d.log.Error("dns forwarder stopped", "err", err)
		}
	}()

	tick := time.NewTicker(c.Health.Interval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
			d.checkHealth(ctx)
			d.reconcile(ctx)
		case <-d.trigger:
			d.reconcile(ctx)
		}
	}
}

// Trigger requests a reconcile soon (non-blocking).
func (d *Daemon) Trigger() {
	select {
	case d.trigger <- struct{}{}:
	default:
	}
}

// reconcile converges the host to config + switches + health.
func (d *Daemon) reconcile(ctx context.Context) {
	c := d.cfg.Get()
	now := d.now()
	d.mu.Lock()
	defer d.mu.Unlock()

	d.syncIngresses(c, now)

	// egress interfaces
	var specs []egress.Spec
	for _, e := range c.Egresses {
		rt := d.runtime(e.Name)
		if !e.Enabled {
			continue
		}
		if !rt.endpoint.IsValid() {
			d.resolve(ctx, e, rt)
		}
		specs = append(specs, egress.SpecFor(e, c.Server.MTU, rt.endpoint))
	}
	for name := range d.egresses {
		if _, ok := c.Egress(name); !ok {
			delete(d.egresses, name)
		}
	}
	if err := d.sys.SyncEgresses(specs); err != nil {
		d.log.Error("sync egresses", "err", err)
	}

	// decisions
	sw := d.state.Switches()
	sel := d.selectorEgresses(c)
	if len(selector.Usable(sel)) > 0 {
		d.clearDirectConfirmations(sw)
		sw = d.state.Switches()
	}
	g := selector.Global{Strategy: c.Selection.Strategy, Fixed: c.Selection.Fixed, Offline: c.Selection.Offline,
		AllowDirect: c.Server.AllowDirect, KillSwitch: sw.KillSwitch, Fast: sw.Fast}
	next := map[string]selector.Target{}
	var changed []netip.Addr
	rp := routing.Plan{ClientNet: c.ClientNet()}
	fp := firewall.Plan{AWGIfaces: c.IngressIfaces(), Isolated: isolatedIfaces(c), ServerAddr: c.ServerIP(), ClientNet: c.ClientNet(),
		PortalPort: c.Web.Portal.Port, AdminPort: adminPort(c.Web.Admin.Listen), AdminIfaces: c.Server.AdminInterfaces}
	for _, e := range c.Egresses {
		if e.Enabled {
			rp.Egresses = append(rp.Egresses, routing.Egress{Iface: e.Iface(), Table: e.Table()})
			fp.EgressIfaces = append(fp.EgressIfaces, e.Iface())
		}
	}
	for _, cl := range c.Clients {
		if !cl.Active(now) {
			continue
		}
		cs := sw.Clients[cl.Name]
		t := selector.Decide(g, sel, selector.Client{Name: cl.Name, Strategy: cl.Strategy, Fixed: cl.Fixed,
			Fast: cs.Fast, Block: cs.Block, DirectConfirmed: cs.DirectConfirmed})
		next[cl.Name] = t
		rc := routing.Client{Addr: cl.Address}
		switch t.Kind {
		case selector.KindEgress:
			e, _ := c.Egress(t.Egress)
			rc.Table = e.Table()
		case selector.KindDirect:
			rc.Table = routing.TableMain
			fp.DirectClients = append(fp.DirectClients, cl.Address)
		case selector.KindPortal:
			fp.PortalClients = append(fp.PortalClients, cl.Address)
		}
		if t.Kind == selector.KindBlock || t.Kind == selector.KindPortal {
			rp.Blocked = append(rp.Blocked, cl.Address)
		}
		rp.Clients = append(rp.Clients, rc)
		if old, ok := d.decisions[cl.Name]; ok && (old.Kind != t.Kind || old.Egress != t.Egress) {
			changed = append(changed, cl.Address)
			d.event("switched", cl.Name, describe(old), describe(t), "@reason."+string(t.Reason))
		}
	}
	d.decisions = next
	fp.LockdownSSH = d.sshLocked(c)

	rules := fp.Rules()
	if r := firewall.Render(rules); r != d.lastFW {
		if err := d.sys.ApplyFirewall(rules); err != nil {
			d.log.Error("firewall", "err", err)
		} else {
			d.lastFW = r
		}
	}
	d.applyProtection(c)
	d.basePlan = rp
	d.learned.Forget(func(route string) bool { _, ok := c.Route(route); return ok })
	d.applyRouting(c, sw.KillSwitch, now)
	if err := d.sys.FlushConntrack(changed); err != nil {
		d.log.Warn("conntrack flush", "err", err)
	}
	d.publish(d.buildStatus(c, sw, now))
}

// syncIngresses converges the ingress interfaces and their peers. Caller
// holds d.mu.
func (d *Daemon) syncIngresses(c *config.Config, now time.Time) {
	want := map[string]bool{}
	for _, sp := range ingress.Specs(c) {
		want[sp.Name] = true
		if old, ok := d.ingSpecs[sp.Name]; !ok || old != sp {
			if err := d.sys.IngressUp(sp); err != nil {
				d.log.Error("ingress update", "iface", sp.Name, "err", err)
				continue
			}
			d.ingSpecs[sp.Name] = sp
		}
	}
	for iface := range d.ingSpecs {
		if !want[iface] {
			if err := d.sys.IngressDown(iface); err != nil {
				d.log.Error("ingress removal", "iface", iface, "err", err)
			}
			delete(d.ingSpecs, iface)
		}
	}
	for _, in := range c.Ingresses {
		if _, up := d.ingSpecs[in.Interface]; !up {
			continue
		}
		if err := d.sys.SyncPeers(in.Interface, ingress.Peers(c, in, now)); err != nil {
			d.log.Error("sync peers", "iface", in.Interface, "err", err)
		}
	}
}

func (d *Daemon) runtime(name string) *egressRuntime {
	rt, ok := d.egresses[name]
	if !ok {
		rt = &egressRuntime{}
		d.egresses[name] = rt
	}
	return rt
}

func (d *Daemon) selectorEgresses(c *config.Config) []selector.Egress {
	out := make([]selector.Egress, 0, len(c.Egresses))
	for _, e := range c.Egresses {
		healthy := false
		if rt, ok := d.egresses[e.Name]; ok {
			healthy = rt.tracker.Healthy()
		}
		out = append(out, selector.Egress{Name: e.Name, Enabled: e.Enabled, Healthy: healthy,
			Priority: e.Priority, Weight: e.Weight})
	}
	return out
}

// clearDirectConfirmations implements "return automatically once an egress
// is back": confirmations for the offline direct exit expire.
func (d *Daemon) clearDirectConfirmations(sw state.Switches) {
	needs := false
	for _, cs := range sw.Clients {
		needs = needs || cs.DirectConfirmed
	}
	if !needs {
		return
	}
	_ = d.state.Update(func(s *state.Switches) {
		for k, v := range s.Clients {
			v.DirectConfirmed = false
			s.Clients[k] = v
		}
	})
}

func (d *Daemon) resolve(ctx context.Context, e config.Egress, rt *egressRuntime) {
	ep, err := dns.ResolveEndpoint(ctx, d.res, e.Endpoint, e.Resolve)
	rt.resolved = d.now()
	if err != nil {
		rt.lastErr = err.Error()
		d.log.Warn("resolve endpoint", "egress", e.Name, "err", err)
		return
	}
	if ep != rt.endpoint && rt.endpoint.IsValid() {
		d.event("endpoint", e.Name, rt.endpoint.String(), ep.String())
	}
	rt.endpoint = ep
}

// checkHealth runs one round of checks for all enabled egresses.
func (d *Daemon) checkHealth(ctx context.Context) {
	c := d.cfg.Get()
	now := d.now()
	type result struct {
		name    string
		stats   egress.Stats
		statErr error
		ok, n   int
		latency time.Duration
		probErr string
	}
	results := make(chan result)
	count := 0
	for _, e := range c.Egresses {
		if !e.Enabled {
			continue
		}
		count++
		go func(e config.Egress) {
			r := result{name: e.Name}
			r.stats, r.statErr = d.sys.EgressStats(e.Iface())
			targets := e.EffectiveTargets(c.Health)
			r.n = len(targets)
			for _, t := range targets {
				lat, err := d.sys.Probe(ctx, e.Iface(), t, c.Health.Timeout)
				if err == nil {
					r.ok++
					if r.latency == 0 || lat < r.latency {
						r.latency = lat
					}
				} else {
					r.probErr = err.Error()
				}
			}
			results <- r
		}(e)
	}
	collected := make([]result, 0, count)
	for range count {
		collected = append(collected, <-results)
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	for _, r := range collected {
		e, ok := c.Egress(r.name)
		if !ok {
			continue
		}
		rt := d.runtime(r.name)
		age := health.HandshakeAge(now, r.stats.LastHandshake)
		chk := health.Check{HandshakeAge: age, MaxAge: e.EffectiveMaxAge(c.Health), ProbesOK: r.ok, Probes: r.n}
		rt.tracker.Rise, rt.tracker.Fall = c.Health.Rise, c.Health.Fall
		known := rt.tracker.Known()
		if healthy, changed := rt.tracker.Observe(chk.OK()); changed {
			switch {
			case healthy && !known:
				d.event("egress_reachable", r.name)
			case healthy:
				d.event("egress_up", r.name)
			default:
				d.event("egress_down", r.name)
			}
		}
		rt.latency = r.latency
		switch {
		case r.statErr != nil:
			rt.lastErr = r.statErr.Error()
		case r.ok == 0 && r.n > 0:
			rt.lastErr = r.probErr
		default:
			rt.lastErr = ""
		}
		if !rt.prevAt.IsZero() {
			dt := now.Sub(rt.prevAt).Seconds()
			if dt > 0 {
				rt.rxRate = float64(max(0, r.stats.RxBytes-rt.prevStats.RxBytes)) / dt
				rt.txRate = float64(max(0, r.stats.TxBytes-rt.prevStats.TxBytes)) / dt
			}
		}
		rt.prevStats, rt.prevAt, rt.stats = r.stats, now, r.stats

		// DynDNS / changing IPv6 prefixes: re-resolve when the handshake is stale
		if (age < 0 || age > c.Health.ReresolveAfter) && now.Sub(rt.resolved) > c.Health.Interval*3 {
			if _, _, err := config.SplitEndpoint(e.Endpoint); err == nil {
				before := rt.endpoint
				d.resolve(ctx, *e, rt)
				if before != rt.endpoint {
					d.Trigger()
				}
			}
		}
	}
}

// event records a user-visible event (i18n key "event.<key>") and logs it
// in English.
func (d *Daemon) event(key string, args ...string) {
	e := d.state.Log(key, args...)
	d.log.Info(i18n.Msg("en", "event."+e.Key, e.Args))
}

// describe names a target for events: the egress or a translated kind.
func describe(t selector.Target) string {
	if t.Kind == selector.KindEgress {
		return t.Egress
	}
	return "@exit." + string(t.Kind)
}

// sshLocked reports whether SSH is restricted to the admin interfaces: only
// once one of them (other than lo) is up, so SSH never locks itself out.
func (d *Daemon) sshLocked(c *config.Config) bool {
	return c.Server.LockdownSSH && slices.ContainsFunc(c.Server.AdminInterfaces, func(i string) bool {
		return i != "lo" && !slices.Contains(c.IngressIfaces(), i) && d.sys.InterfaceUp(i)
	})
}

func isolatedIfaces(c *config.Config) []string {
	var out []string
	for _, in := range c.Ingresses {
		if in.Isolated {
			out = append(out, in.Interface)
		}
	}
	return out
}

func adminPort(listen string) uint16 {
	ap, err := netip.ParseAddrPort(listen)
	if err == nil {
		return ap.Port()
	}
	if _, port, err := config.SplitEndpoint("x" + listen); err == nil { // ":443"
		return port
	}
	return 0
}
