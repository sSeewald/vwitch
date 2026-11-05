package daemon

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/sseewald/vwitch/internal/config"
	"github.com/sseewald/vwitch/internal/egress"
	"github.com/sseewald/vwitch/internal/exposure"
	"github.com/sseewald/vwitch/internal/firewall"
	"github.com/sseewald/vwitch/internal/ingress"
	"github.com/sseewald/vwitch/internal/routing"
	"github.com/sseewald/vwitch/internal/selector"
	"github.com/sseewald/vwitch/internal/state"
)

type fakeSys struct {
	mu        sync.Mutex
	handshake map[string]time.Time // iface -> last handshake
	probeOK   map[string]bool
	routes    routing.Plan
	fw        []firewall.Rule
	flushed   [][]netip.Addr
	peers     []ingress.Peer
	sockets   []exposure.Socket
	addrs     map[string][]netip.Addr // by interface
}

func (f *fakeSys) Prepare() error                        { return nil }
func (f *fakeSys) IngressUp(ingress.Spec) error          { return nil }
func (f *fakeSys) SyncPeers(p []ingress.Peer) error      { f.peers = p; return nil }
func (f *fakeSys) SyncEgresses([]egress.Spec) error      { return nil }
func (f *fakeSys) InterfaceUp(string) bool               { return false }
func (f *fakeSys) InterfaceAddrs(i string) []netip.Addr  { return f.addrs[i] }
func (f *fakeSys) Listening() ([]exposure.Socket, error) { return f.sockets, nil }
func (f *fakeSys) Close() error                          { return nil }
func (f *fakeSys) ApplyRouting(p routing.Plan) error     { f.routes = p; return nil }
func (f *fakeSys) ApplyFirewall(r []firewall.Rule) error { f.fw = r; return nil }
func (f *fakeSys) PeerStats() (map[string]ingress.PeerStats, error) {
	return map[string]ingress.PeerStats{}, nil
}
func (f *fakeSys) FlushConntrack(a []netip.Addr) error {
	if len(a) > 0 {
		f.flushed = append(f.flushed, a)
	}
	return nil
}
func (f *fakeSys) EgressStats(iface string) (egress.Stats, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return egress.Stats{LastHandshake: f.handshake[iface]}, nil
}
func (f *fakeSys) Probe(_ context.Context, iface string, _ config.Target, _ time.Duration) (time.Duration, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.probeOK[iface] {
		return time.Millisecond, nil
	}
	return 0, errors.New("timeout")
}

func key() string { k, _ := wgtypes.GeneratePrivateKey(); return k.String() }

func setup(t *testing.T) (*Daemon, *fakeSys, *time.Time) {
	t.Helper()
	c := config.New()
	c.Server.PrivateKey = key()
	c.Server.Endpoint = "203.0.113.1"
	c.Server.AllowDirect = true
	c.Server.AWG = config.AWGParams{Jc: 4, Jmin: 40, Jmax: 200, S1: 10, S2: 20, H1: "1-2", H2: "3-4", H3: "5-6", H4: "7-8"}
	for i, n := range []string{"home", "office"} {
		c.Egresses = append(c.Egresses, config.Egress{Name: n, Index: i + 1, Enabled: true, Priority: (i + 1) * 10,
			Endpoint: "192.0.2.1:51820", Address: netip.MustParseAddr("192.168.1.2"), PrivateKey: key(), PublicKey: key()})
	}
	c.ApplyDefaults()
	dir := t.TempDir()
	cs, err := config.Create(dir+"/vwitch.yaml", c)
	if err != nil {
		t.Fatal(err)
	}
	st, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_000_000, 0)
	sys := &fakeSys{handshake: map[string]time.Time{}, probeOK: map[string]bool{}}
	d := New(cs, st, sys, slog.New(slog.NewTextHandler(io.Discard, nil)))
	d.now = func() time.Time { return now }
	if _, err := d.AddClient("phone", ClientOptions{}); err != nil {
		t.Fatal(err)
	}
	return d, sys, &now
}

func (f *fakeSys) setUp(iface string, up bool, now time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if up {
		f.handshake[iface] = now.Add(-10 * time.Second)
	} else {
		f.handshake[iface] = time.Time{}
	}
	f.probeOK[iface] = up
}

func exitOf(d *Daemon, name string) string {
	for _, c := range d.Status().Clients {
		if c.Name == name {
			if c.Exit == "egress" {
				return c.Egress
			}
			return c.Exit
		}
	}
	return "?"
}

func TestFailoverAndSwitches(t *testing.T) {
	d, sys, now := setup(t)
	ctx := context.Background()

	// nothing healthy yet: fail-safe block, unreachable rule present
	d.reconcile(ctx)
	if got := exitOf(d, "phone"); got != "block" {
		t.Fatalf("initial exit %s", got)
	}
	rules := sys.routes.Rules()
	if last := rules[len(rules)-1]; !last.Unreachable {
		t.Fatal("fail-safe rule missing")
	}

	sys.setUp("vwe1", true, *now)
	sys.setUp("vwe2", true, *now)
	d.checkHealth(ctx)
	d.reconcile(ctx)
	if got := exitOf(d, "phone"); got != "home" {
		t.Fatalf("want home, got %s", got)
	}

	// home fails: hysteresis needs Fall (3) bad checks
	sys.setUp("vwe1", false, *now)
	for i := range 3 {
		d.checkHealth(ctx)
		d.reconcile(ctx)
		if i < 2 && exitOf(d, "phone") != "home" {
			t.Fatal("switched before hysteresis")
		}
	}
	if got := exitOf(d, "phone"); got != "office" {
		t.Fatalf("want office, got %s", got)
	}
	if len(sys.flushed) != 2 { // block->home, home->office
		t.Fatalf("conntrack flushes %v", sys.flushed)
	}

	// kill switch
	on := true
	if err := d.SetGlobal(&on, nil); err != nil {
		t.Fatal(err)
	}
	d.reconcile(ctx)
	if got := exitOf(d, "phone"); got != "block" {
		t.Fatalf("kill switch: %s", got)
	}
	for _, r := range sys.fw {
		if r.Chain == firewall.ChainForward && r.IIF == "awg0" && r.Verdict == firewall.Accept && r.Saddr.IsValid() {
			t.Fatalf("direct rule while kill switch on: %s", r)
		}
	}
	ev := d.Status().Events
	if len(ev) == 0 || ev[len(ev)-1].Key != "switched" || ev[len(ev)-1].Args[0] != "phone" ||
		ev[len(ev)-1].Args[3] != "@reason."+string(selector.ReasonKillSwitch) {
		t.Fatalf("events %v", ev)
	}
}

func TestOfflineAskThenAutoReturn(t *testing.T) {
	d, sys, now := setup(t)
	ctx := context.Background()
	if err := d.Set("offline", "ask"); err != nil {
		t.Fatal(err)
	}
	d.reconcile(ctx)
	if got := exitOf(d, "phone"); got != "portal" {
		t.Fatalf("want portal, got %s", got)
	}
	if route, ok := d.dnsRoute(netip.MustParseAddr("10.8.0.2")); !ok || route != "" {
		t.Fatal("portal client must resolve DNS directly")
	}
	if err := d.SetClientSwitch("phone", config.ActionDirect, true); err != nil {
		t.Fatal(err)
	}
	d.reconcile(ctx)
	if got := exitOf(d, "phone"); got != "direct" {
		t.Fatalf("want direct, got %s", got)
	}
	sys.setUp("vwe2", true, *now)
	d.checkHealth(ctx)
	d.reconcile(ctx)
	if got := exitOf(d, "phone"); got != "office" {
		t.Fatalf("want office after egress returned, got %s", got)
	}
	if d.state.Switches().Clients["phone"].DirectConfirmed {
		t.Fatal("direct confirmation must expire when an egress is back")
	}
}

func TestRemoveClientOffboards(t *testing.T) {
	d, sys, _ := setup(t)
	d.reconcile(context.Background())
	if len(sys.peers) != 1 {
		t.Fatal("peer missing")
	}
	if err := d.RemoveClient("phone"); err != nil {
		t.Fatal(err)
	}
	d.reconcile(context.Background())
	if len(sys.peers) != 0 {
		t.Fatal("peer still configured")
	}
}

func TestSecurity(t *testing.T) {
	d, sys, _ := setup(t)
	sock := func(proto, addr string) exposure.Socket {
		return exposure.Socket{Proto: proto, Addr: netip.MustParseAddrPort(addr), Inode: 1}
	}
	sys.sockets = []exposure.Socket{
		sock("tcp", "0.0.0.0:22"),     // ssh, not locked down
		sock("udp", "0.0.0.0:51845"),  // ingress
		sock("tcp", "0.0.0.0:8090"),   // admin, restricted by firewall
		sock("tcp", "10.8.0.1:80"),    // portal on the client net
		sock("tcp", "127.0.0.1:5432"), // loopback
		sock("tcp", "[::]:3306"),      // database: exposed
	}
	sys.addrs = map[string][]netip.Addr{"eth0": {netip.MustParseAddr("203.0.113.9")}, "wt0": {netip.MustParseAddr("100.92.0.5")}}
	sec := d.Security()
	if len(sec.Ports) != 2 || sec.Ports[0].Addr.Port() != 22 || sec.Ports[1].Addr.Port() != 3306 || !sec.SSHOpen {
		t.Fatalf("ports %v", sec.Ports)
	}
	if len(sec.PublicAdmin) != 0 { // only "lo" is an admin interface
		t.Fatalf("public admin %v", sec.PublicAdmin)
	}
	if err := d.Set("admin_interfaces", "lo, wt0, eth0"); err != nil {
		t.Fatal(err)
	}
	if sec = d.Security(); len(sec.PublicAdmin) != 1 || sec.PublicAdmin[0] != "eth0" {
		t.Fatalf("public admin %v", sec.PublicAdmin)
	}
}
