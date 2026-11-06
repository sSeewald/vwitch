package daemon

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sseewald/vwitch/internal/activity"
	"github.com/sseewald/vwitch/internal/blocking"
	"github.com/sseewald/vwitch/internal/config"
	"github.com/sseewald/vwitch/internal/domains"
	"github.com/sseewald/vwitch/internal/firewall"
	"github.com/sseewald/vwitch/internal/geo"
	"github.com/sseewald/vwitch/internal/nflog"
	"github.com/sseewald/vwitch/internal/version"
)

// protection is the runtime of blocking and activity: the domain matcher
// the DNS forwarder asks, the block log, the domain list, the traffic
// history and the country database.
type protection struct {
	log     *blocking.Log
	domains *activity.Domains
	traffic *activity.Traffic
	matcher atomic.Pointer[blocking.Matcher]
	names   atomic.Pointer[map[netip.Addr]string] // client address -> name

	// guarded by Daemon.mu
	matcherKey string
	lastBlock  string

	geoMu   sync.Mutex
	geo     *geo.DB
	geoErr  string
	geoBusy bool
	geoWake chan struct{}
}

const (
	blockLogSize   = 1000
	domainKeep     = 24 * time.Hour
	domainMax      = 5000
	geoMaxAge      = 7 * 24 * time.Hour
	geoRetry       = time.Hour
	geoTimeout     = 10 * time.Minute
	trafficEvery   = 10 * time.Second
	trafficSaveDue = 5 * time.Minute
	geoFile        = "geo.db.gz"
	trafficFile    = "traffic.json"
)

func newProtection() protection {
	return protection{
		log:     blocking.NewLog(blockLogSize),
		domains: activity.NewDomains(domainKeep, domainMax),
		traffic: activity.NewTraffic(),
		geoWake: make(chan struct{}, 1),
	}
}

func (d *Daemon) statePath(name string) string { return filepath.Join(d.state.Dir(), name) }

// runProtection loads saved data and runs the background loops until ctx
// ends.
func (d *Daemon) runProtection(ctx context.Context) {
	p := &d.prot
	if f, err := os.Open(d.statePath(geoFile)); err == nil {
		db, err := geo.Load(f)
		_ = f.Close()
		if err != nil {
			d.log.Warn("country database not loaded", "err", err)
		} else {
			p.geoMu.Lock()
			p.geo = db
			p.geoMu.Unlock()
			d.Trigger()
		}
	}
	if f, err := os.Open(d.statePath(trafficFile)); err == nil {
		if err := p.traffic.Load(f); err != nil {
			d.log.Warn("traffic history not loaded", "err", err)
		}
		_ = f.Close()
	}
	go func() {
		if err := d.sys.ListenBlocked(ctx, d.onBlocked); err != nil {
			d.log.Warn("block log of connections unavailable", "err", err)
		}
	}()
	go d.geoLoop(ctx)

	tick := time.NewTicker(trafficEvery)
	defer tick.Stop()
	saved := d.now()
	for {
		select {
		case <-ctx.Done():
			d.saveTraffic()
			return
		case <-tick.C:
			d.sampleTraffic()
			if d.now().Sub(saved) >= trafficSaveDue {
				d.saveTraffic()
				saved = d.now()
			}
		}
	}
}

// sampleTraffic feeds the per-client byte counters into the history.
func (d *Daemon) sampleTraffic() {
	stats, err := d.sys.PeerStats()
	if err != nil {
		return
	}
	c := d.cfg.Get()
	cum := map[string]activity.Counter{}
	for _, cl := range c.Clients {
		if s, ok := stats[cl.PublicKey]; ok { // the server sends what the client downloads
			cum[cl.Name] = activity.Counter{Down: s.TxBytes, Up: s.RxBytes}
		}
	}
	d.prot.traffic.Observe(d.now(), cum)
}

func (d *Daemon) saveTraffic() {
	if err := writeAtomic(d.statePath(trafficFile), d.prot.traffic.Save); err != nil {
		d.log.Warn("traffic history not saved", "err", err)
	}
}

// writeAtomic writes a file through a temporary one.
func writeAtomic(path string, write func(io.Writer) error) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if err := errors.Join(write(f), f.Close()); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

// geoLoop keeps the country database fresh while region filtering is on.
func (d *Daemon) geoLoop(ctx context.Context) {
	p := &d.prot
	t := time.NewTicker(geoRetry)
	defer t.Stop()
	for {
		c := d.cfg.Get()
		p.geoMu.Lock()
		due := c.Security.Regions.Active() && (p.geo == nil || d.now().Sub(p.geo.Updated) > geoMaxAge)
		p.geoMu.Unlock()
		if due {
			d.updateGeo(ctx)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-p.geoWake:
		}
	}
}

func (d *Daemon) updateGeo(ctx context.Context) {
	p := &d.prot
	p.geoMu.Lock()
	p.geoBusy = true
	p.geoMu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, geoTimeout)
	defer cancel()
	db, err := geo.Fetch(ctx, &http.Client{Timeout: geoTimeout}, geo.Sources, "vwitch/"+version.String(), d.now())
	if err == nil {
		err = writeAtomic(d.statePath(geoFile), db.Save)
	}
	p.geoMu.Lock()
	p.geoBusy = false
	if err != nil {
		p.geoErr = err.Error()
	} else {
		p.geo, p.geoErr = db, ""
	}
	p.geoMu.Unlock()
	if err != nil {
		d.log.Warn("country database update failed", "err", err)
		return
	}
	d.log.Info("country database updated", "ranges", db.Len())
	d.Trigger()
}

func (d *Daemon) geoDB() *geo.DB {
	d.prot.geoMu.Lock()
	defer d.prot.geoMu.Unlock()
	return d.prot.geo
}

// applyProtection converges the matcher, the client names and the block
// table. Caller holds d.mu.
func (d *Daemon) applyProtection(c *config.Config) {
	p := &d.prot
	if key := slicesKey(c.Security.BlockedDomains); key != p.matcherKey || p.matcher.Load() == nil {
		p.matcher.Store(blocking.NewMatcher(blocking.DomainSource{Name: blocking.SourceCustom, Domains: c.Security.BlockedDomains}))
		p.matcherKey = key
	}
	names := map[netip.Addr]string{}
	for _, cl := range c.Clients {
		names[cl.Address] = cl.Name
	}
	p.names.Store(&names)
	if c.Security.NoActivity {
		p.domains.Clear()
	}

	plan := firewall.BlockPlan{AWGIfaces: c.IngressIfaces()}
	r := c.Security.Regions
	if r.Active() {
		if db := d.geoDB(); db != nil {
			plan.Filters = append(plan.Filters, blocking.Filter{Source: blocking.SourceRegion,
				Outgoing: r.Outgoing(), Incoming: r.Incoming(), Allow: r.Mode == config.RegionAllow,
				Ranges: db.Ranges(r.Countries)})
		} else {
			select {
			case p.geoWake <- struct{}{}:
			default:
			}
		}
	}
	sets, rules := plan.Build()
	if s := firewall.RenderBlock(sets, rules); s != p.lastBlock {
		if err := d.sys.ApplyBlock(sets, rules); err != nil {
			d.log.Error("block table", "err", err)
			return
		}
		p.lastBlock = s
	}
}

func slicesKey(s []string) string {
	b := make([]byte, 0, 16*len(s))
	for _, x := range s {
		b = append(b, x...)
		b = append(b, 0)
	}
	return string(b)
}

func (d *Daemon) clientName(a netip.Addr) string {
	if m := d.prot.names.Load(); m != nil {
		return (*m)[a]
	}
	return ""
}

// dnsBlock is the forwarder's Block hook.
func (d *Daemon) dnsBlock(_ netip.Addr, name string) (string, bool) {
	s, _, ok := d.prot.matcher.Load().Match(name)
	return s, ok
}

// dnsSeen is the forwarder's Seen hook.
func (d *Daemon) dnsSeen(client netip.Addr, name, source string) {
	now := d.now()
	who := d.clientName(client)
	if !d.cfg.Get().Security.NoActivity {
		d.prot.domains.Seen(who, name, source != "", now)
	}
	if source != "" {
		d.prot.log.Add(blocking.Event{Time: now, Source: source, Client: who, Domain: name})
	}
}

// onBlocked records a connection the block table rejected.
func (d *Daemon) onBlocked(h nflog.Hit) {
	source, incoming, ok := firewall.ParseLogPrefix(h.Prefix)
	if !ok {
		return
	}
	e := blocking.Event{Time: d.now(), Source: source, Incoming: incoming, Proto: nflog.ProtoName(h.Proto), Port: h.DPort}
	if incoming {
		e.Addr = h.Src
	} else {
		e.Addr, e.Client = h.Dst, d.clientName(h.Src)
	}
	e.Country = d.geoDB().Country(e.Addr)
	d.prot.log.Add(e)
}

// --- operations for CLI and UI ---

// BlockDomain adds domains to the block list.
func (d *Daemon) BlockDomain(list ...string) error {
	return d.update(func(c *config.Config) error {
		for _, s := range list {
			n, err := domains.Normalize(s)
			if err != nil {
				return err
			}
			if slices.Contains(c.Security.BlockedDomains, n) {
				continue
			}
			c.Security.BlockedDomains = append(c.Security.BlockedDomains, n)
		}
		slices.Sort(c.Security.BlockedDomains)
		return nil
	})
}

// UnblockDomain removes domains from the block list.
func (d *Daemon) UnblockDomain(list ...string) error {
	return d.update(func(c *config.Config) error {
		for _, s := range list {
			n, err := domains.Normalize(s)
			if err != nil {
				return err
			}
			c.Security.BlockedDomains = slices.DeleteFunc(c.Security.BlockedDomains, func(x string) bool { return x == n })
		}
		return nil
	})
}

// BlockLog returns recent block events; kind "domain" or "address" filters.
func (d *Daemon) BlockLog(n int, kind string) []blocking.Event {
	var keep func(blocking.Event) bool
	switch kind {
	case "domain":
		keep = func(e blocking.Event) bool { return e.Domain != "" }
	case "address":
		keep = func(e blocking.Event) bool { return e.Domain == "" }
	}
	return d.prot.log.Recent(n, keep)
}

// Domains returns the looked-up domains of the last day (one client or all).
func (d *Daemon) Domains(client string) []activity.DomainStat {
	return d.prot.domains.List(client, d.now())
}

// Traffic returns one series of the traffic history.
func (d *Daemon) Traffic(rangeName, client string) (activity.Range, []activity.Point) {
	r := activity.RangeByName(rangeName)
	return r, d.prot.traffic.Series(r, client, d.now())
}

// TrafficTotals returns the bytes per client within a range.
func (d *Daemon) TrafficTotals(rangeName string) map[string]activity.Counter {
	return d.prot.traffic.Totals(activity.RangeByName(rangeName), d.now())
}

// GeoStatus describes the country database.
type GeoStatus struct {
	Updated time.Time `json:"updated"`
	Ranges  int       `json:"ranges"`
	Busy    bool      `json:"busy"`
	Error   string    `json:"error,omitempty"`
}

// Geo returns the state of the country database.
func (d *Daemon) Geo() GeoStatus {
	p := &d.prot
	p.geoMu.Lock()
	defer p.geoMu.Unlock()
	s := GeoStatus{Ranges: p.geo.Len(), Busy: p.geoBusy, Error: p.geoErr}
	if p.geo != nil {
		s.Updated = p.geo.Updated
	}
	return s
}
