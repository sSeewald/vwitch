package daemon

import (
	"cmp"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"time"

	"github.com/sseewald/vwitch/internal/config"
	"github.com/sseewald/vwitch/internal/domains"
	"github.com/sseewald/vwitch/internal/routing"
	"github.com/sseewald/vwitch/internal/selector"
)

// Domain routing: the DNS forwarder asks dnsRoute where a query goes and
// reports the answer to learn before the client sees it. learn adds the
// addresses to the routing plan at once, so the first connection already
// takes the route's egress. Kill switch and blocked clients always win; a
// route whose egress is down falls back to the client's normal exit.

// RouteStatus describes one domain route.
type RouteStatus struct {
	Name    string   `json:"name"`
	Egress  string   `json:"egress"`
	Domains []string `json:"domains"`
	Active  bool     `json:"active"`  // egress up: traffic follows the route
	Learned int      `json:"learned"` // addresses learned from DNS
}

func routeList(c *config.Config) []domains.Route {
	out := make([]domains.Route, len(c.Routes))
	for i, r := range c.Routes {
		out[i] = domains.Route{Name: r.Name, Domains: r.Domains}
	}
	return out
}

// routeEgress returns the egress a route currently uses. Caller holds d.mu.
func (d *Daemon) routeEgress(c *config.Config, route string) (*config.Egress, bool) {
	r, ok := c.Route(route)
	if !ok {
		return nil, false
	}
	e, ok := c.Egress(r.Egress)
	if !ok || !e.Enabled {
		return nil, false
	}
	rt, ok := d.egresses[e.Name]
	return e, ok && rt.tracker.Healthy()
}

// domainRules turns the learned addresses into routing rules. Caller holds d.mu.
func (d *Daemon) domainRules(c *config.Config, killSwitch bool, now time.Time) []routing.Domain {
	if killSwitch || len(c.Routes) == 0 {
		return nil
	}
	var out []routing.Domain
	for route, addrs := range d.learned.Active(now) {
		e, ok := d.routeEgress(c, route)
		if !ok {
			continue
		}
		for _, a := range addrs {
			out = append(out, routing.Domain{Dst: a, Table: e.Table()})
		}
	}
	slices.SortFunc(out, func(a, b routing.Domain) int { return a.Dst.Compare(b.Dst) })
	return out
}

// applyRouting adds the domain rules to the base plan and applies it.
// Caller holds d.mu.
func (d *Daemon) applyRouting(c *config.Config, killSwitch bool, now time.Time) {
	p := d.basePlan
	p.Domains = d.domainRules(c, killSwitch, now)
	if err := d.sys.ApplyRouting(p); err != nil {
		d.log.Error("routing", "err", err)
	}
}

// dnsRoute tells the DNS forwarder where a client's query for name may go:
// through the egress of a matching domain route, else the client's exit.
func (d *Daemon) dnsRoute(client netip.Addr, name string) (string, bool) {
	c := d.cfg.Get()
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, cl := range c.Clients {
		if cl.Address != client {
			continue
		}
		t := d.decisions[cl.Name]
		switch t.Kind {
		case selector.KindEgress, selector.KindDirect:
			if route, ok := domains.Match(routeList(c), name); ok {
				if e, ok := d.routeEgress(c, route); ok {
					return e.Iface(), true
				}
			}
			if t.Kind == selector.KindDirect {
				return "", true
			}
			e, ok := c.Egress(t.Egress)
			return e.Iface(), ok
		case selector.KindPortal:
			return "", true
		}
		return "", false
	}
	return "", false
}

// learn records the addresses of a DNS answer for a routed name and updates
// routing at once if a new address appeared.
func (d *Daemon) learn(name string, addrs []netip.Addr, ttl time.Duration) {
	c := d.cfg.Get()
	route, ok := domains.Match(routeList(c), name)
	if !ok {
		return
	}
	now := d.now()
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.learned.Learn(route, addrs, ttl, now) {
		d.log.Debug("domain route learned", "route", route, "name", name, "addrs", addrs)
		d.applyRouting(c, d.state.Switches().KillSwitch, now)
		st := d.status
		st.Routes = d.routeStatus(c, now)
		d.publish(st)
	}
}

// routeStatus reports all routes. Caller holds d.mu.
func (d *Daemon) routeStatus(c *config.Config, now time.Time) []RouteStatus {
	active := d.learned.Active(now)
	out := make([]RouteStatus, 0, len(c.Routes))
	for _, r := range c.Routes {
		_, ok := d.routeEgress(c, r.Name)
		out = append(out, RouteStatus{Name: r.Name, Egress: r.Egress, Domains: r.Domains,
			Active: ok, Learned: len(active[r.Name])})
	}
	return out
}

// NormalizeDomains cleans, de-duplicates and sorts user input.
func NormalizeDomains(in []string) ([]string, error) {
	var out []string
	var errs []error
	for _, s := range in {
		d, err := domains.Normalize(s)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		out = append(out, d)
	}
	slices.Sort(out)
	return slices.Compact(out), errors.Join(errs...)
}

// SetRoute creates or replaces a domain route.
func (d *Daemon) SetRoute(name, egress string, list []string) error {
	ds, err := NormalizeDomains(list)
	if err != nil {
		return err
	}
	if len(ds) == 0 {
		return errors.New("no domains")
	}
	created := false
	err = d.update(func(c *config.Config) error {
		if err := config.ValidateName(name); err != nil {
			return err
		}
		for _, o := range c.Routes {
			for _, dom := range ds {
				if o.Name != name && slices.Contains(o.Domains, dom) {
					return fmt.Errorf("%s is already in route %q", dom, o.Name)
				}
			}
		}
		r := config.Route{Name: name, Egress: egress, Domains: ds}
		if old, ok := c.Route(name); ok {
			*old = r
		} else {
			c.Routes = append(c.Routes, r)
			created = true
		}
		slices.SortFunc(c.Routes, func(a, b config.Route) int { return cmp.Compare(a.Name, b.Name) })
		return nil
	})
	if err == nil {
		key := "route_changed"
		if created {
			key = "route_added"
		}
		d.event(key, name, egress)
	}
	return err
}

// RemoveRoute deletes a domain route.
func (d *Daemon) RemoveRoute(name string) error {
	err := d.update(func(c *config.Config) error {
		n := len(c.Routes)
		c.Routes = slices.DeleteFunc(c.Routes, func(r config.Route) bool { return r.Name == name })
		if len(c.Routes) == n {
			return fmt.Errorf("unknown route %q", name)
		}
		return nil
	})
	if err == nil {
		d.event("route_removed", name)
	}
	return err
}

// RouteDomain sends one domain through an egress: it joins the first route
// of that egress (or a new route named after it) and leaves any other route.
// A route left without domains is removed.
func (d *Daemon) RouteDomain(domain, egress string) error {
	dom, err := domains.Normalize(domain)
	if err != nil {
		return err
	}
	var target string
	err = d.update(func(c *config.Config) error {
		if _, ok := c.Egress(egress); !ok {
			return fmt.Errorf("unknown egress %q", egress)
		}
		for i := range c.Routes {
			c.Routes[i].Domains = slices.DeleteFunc(c.Routes[i].Domains, func(x string) bool { return x == dom })
		}
		c.Routes = slices.DeleteFunc(c.Routes, func(r config.Route) bool { return len(r.Domains) == 0 })
		for i := range c.Routes {
			if r := &c.Routes[i]; r.Egress == egress {
				r.Domains = append(r.Domains, dom)
				slices.Sort(r.Domains)
				target = r.Name
				return nil
			}
		}
		target = egress
		if _, taken := c.Route(target); taken {
			return fmt.Errorf("route %q exists for another egress", target)
		}
		c.Routes = append(c.Routes, config.Route{Name: target, Egress: egress, Domains: []string{dom}})
		slices.SortFunc(c.Routes, func(a, b config.Route) int { return cmp.Compare(a.Name, b.Name) })
		return nil
	})
	if err == nil {
		d.event("route_changed", target, egress)
	}
	return err
}
