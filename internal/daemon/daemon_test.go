package daemon

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/sseewald/vwitch/internal/config"
	"github.com/sseewald/vwitch/internal/egress"
	"github.com/sseewald/vwitch/internal/exposure"
	"github.com/sseewald/vwitch/internal/firewall"
	"github.com/sseewald/vwitch/internal/ingress"
	"github.com/sseewald/vwitch/internal/nflog"
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
	block     []firewall.Rule
	blockSets []firewall.Set
	flushed   [][]netip.Addr
	peers     map[string][]ingress.Peer // by ingress interface
	ingresses map[string]ingress.Spec
	sockets   []exposure.Socket
	addrs     map[string][]netip.Addr // by interface
	up        map[string]bool
}

func (f *fakeSys) Prepare() error { return nil }
func (f *fakeSys) IngressUp(s ingress.Spec) error {
	if f.ingresses == nil {
		f.ingresses = map[string]ingress.Spec{}
	}
	f.ingresses[s.Name] = s
	return nil
}
func (f *fakeSys) IngressDown(i string) error { delete(f.ingresses, i); delete(f.peers, i); return nil }
func (f *fakeSys) SyncPeers(i string, p []ingress.Peer) error {
	if f.peers == nil {
		f.peers = map[string][]ingress.Peer{}
	}
	f.peers[i] = p
	return nil
}
func (f *fakeSys) SyncEgresses([]egress.Spec) error      { return nil }
func (f *fakeSys) InterfaceUp(i string) bool             { return f.up[i] }
func (f *fakeSys) InterfaceAddrs(i string) []netip.Addr  { return f.addrs[i] }
func (f *fakeSys) Listening() ([]exposure.Socket, error) { return f.sockets, nil }
func (f *fakeSys) Close() error                          { return nil }
func (f *fakeSys) ApplyRouting(p routing.Plan) error     { f.routes = p; return nil }
func (f *fakeSys) ApplyFirewall(r []firewall.Rule) error { f.fw = r; return nil }
func (f *fakeSys) ApplyBlock(s []firewall.Set, r []firewall.Rule) error {
	f.blockSets, f.block = s, r
	return nil
}
func (f *fakeSys) ListenBlocked(ctx context.Context, _ func(nflog.Hit)) error {
	<-ctx.Done()
	return nil
}
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
	c.Ingresses[0].AWG = config.AWGParams{Jc: 4, Jmin: 40, Jmax: 200, S1: 10, S2: 20, H1: "1-2", H2: "3-4", H3: "5-6", H4: "7-8"}
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
	if route, ok := d.dnsRoute(netip.MustParseAddr("10.8.0.2"), "example.org"); !ok || route != "" {
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
	if len(sys.peers["awg0"]) != 1 {
		t.Fatal("peer missing")
	}
	if err := d.RemoveClient("phone"); err != nil {
		t.Fatal(err)
	}
	d.reconcile(context.Background())
	if len(sys.peers["awg0"]) != 0 {
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
		sock("tcp", "0.0.0.0:443"),    // admin, restricted by firewall
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

func TestLockdownIgnoresIngress(t *testing.T) {
	d, sys, _ := setup(t)
	c := d.Config()
	c.Server.AdminInterfaces = []string{"lo", "awg0", "wt0"}
	c.Server.LockdownSSH = true
	sys.up = map[string]bool{"lo": true, "awg0": true}
	if d.sshLocked(c) {
		t.Fatal("awg0 alone must not lock SSH (no client exists yet after install)")
	}
	sys.up["wt0"] = true
	if !d.sshLocked(c) {
		t.Fatal("wt0 up must lock SSH")
	}
}

func TestDisableDirectResetsOffline(t *testing.T) {
	d, _, _ := setup(t)
	if err := d.Set("offline", "ask"); err != nil {
		t.Fatal(err)
	}
	if err := d.Set("allow_direct", "false"); err != nil {
		t.Fatal(err)
	}
	if c := d.Config(); c.Server.AllowDirect || c.Selection.Offline != config.OfflineBlock {
		t.Fatalf("allow_direct=%v offline=%s", c.Server.AllowDirect, c.Selection.Offline)
	}
	// several dependent settings in one change
	if err := d.SetMany([][2]string{{"allow_direct", "true"}, {"offline", "direct"}}); err != nil {
		t.Fatal(err)
	}
	if c := d.Config(); !c.Server.AllowDirect || c.Selection.Offline != config.OfflineDirect {
		t.Fatalf("allow_direct=%v offline=%s", c.Server.AllowDirect, c.Selection.Offline)
	}
	// an invalid combination changes nothing
	if err := d.SetMany([][2]string{{"allow_direct", "false"}, {"offline", "ask"}}); err == nil {
		t.Fatal("want error")
	}
	if c := d.Config(); !c.Server.AllowDirect {
		t.Fatal("failed change must not be applied partially")
	}
}

func domainRulesOf(sys *fakeSys) []string {
	var out []string
	for _, r := range sys.routes.Rules() {
		if r.Priority == routing.PrioDomain || r.Priority == routing.PrioBlocked {
			out = append(out, r.String())
		}
	}
	return out
}

func TestDomainRoutes(t *testing.T) {
	d, sys, now := setup(t)
	ctx := context.Background()
	sys.setUp("vwe1", true, *now)
	sys.setUp("vwe2", true, *now)
	d.checkHealth(ctx)
	d.reconcile(ctx)
	phone := netip.MustParseAddr("10.8.0.2")

	if err := d.SetRoute("google", "office", []string{"https://www.Google.de/x", "*.google.com", "google.de"}); err != nil {
		t.Fatal(err)
	}
	if r, _ := d.Config().Route("google"); !slices.Equal(r.Domains, []string{"google.com", "google.de", "www.google.de"}) {
		t.Fatalf("domains not normalized/sorted: %v", r.Domains)
	}
	if err := d.SetRoute("a-first", "home", []string{"google.de"}); err == nil || !strings.Contains(err.Error(), `google.de is already in route "google"`) {
		t.Fatalf("duplicate across routes: %v", err)
	}
	if err := d.RemoveEgress("office"); err == nil || !strings.Contains(err.Error(), "used by route") {
		t.Fatalf("remove egress in use: %v", err)
	}
	d.reconcile(ctx)

	// DNS for a routed name leaves through the route's egress, others through the client's exit
	if iface, ok := d.dnsRoute(phone, "mail.google.com"); !ok || iface != "vwe2" {
		t.Fatalf("routed dns via %q", iface)
	}
	if iface, _ := d.dnsRoute(phone, "example.org"); iface != "vwe1" {
		t.Fatalf("normal dns via %q", iface)
	}

	// an answer is applied immediately, before any reconcile
	d.learn("mail.google.com", []netip.Addr{netip.MustParseAddr("142.250.0.1")}, time.Minute)
	d.learn("example.org", []netip.Addr{netip.MustParseAddr("93.184.215.14")}, time.Minute)
	want := []string{"75: from 10.8.0.0/24 to 142.250.0.1/32 lookup 51822"}
	if got := domainRulesOf(sys); !slices.Equal(got, want) {
		t.Fatalf("rules %v", got)
	}
	if st := d.Status(); len(st.Routes) != 1 || !st.Routes[0].Active || st.Routes[0].Learned != 1 {
		t.Fatalf("route status %+v", st.Routes)
	}

	// a blocked client must not reach the route
	if err := d.SetClientSwitch("phone", config.ActionBlock, true); err != nil {
		t.Fatal(err)
	}
	d.reconcile(ctx)
	if got := domainRulesOf(sys); len(got) != 2 || got[0] != "72: from 10.8.0.2/32 unreachable" {
		t.Fatalf("blocked client: %v", got)
	}
	_ = d.SetClientSwitch("phone", config.ActionBlock, false)

	// target egress down: fall back to the normal exit
	sys.setUp("vwe2", false, *now)
	for range 3 {
		d.checkHealth(ctx)
	}
	d.reconcile(ctx)
	if got := domainRulesOf(sys); len(got) != 0 {
		t.Fatalf("route to a down egress: %v", got)
	}
	if iface, _ := d.dnsRoute(phone, "google.de"); iface != "vwe1" {
		t.Fatalf("dns must fall back, got %q", iface)
	}
	sys.setUp("vwe2", true, *now)
	d.checkHealth(ctx)
	d.checkHealth(ctx)
	d.reconcile(ctx)

	// kill switch wins
	on := true
	if err := d.SetGlobal(&on, nil); err != nil {
		t.Fatal(err)
	}
	d.reconcile(ctx)
	if got := domainRulesOf(sys); slices.ContainsFunc(got, func(r string) bool { return strings.HasPrefix(r, "75:") }) {
		t.Fatalf("kill switch must drop domain rules: %v", got)
	}
	off := false
	_ = d.SetGlobal(&off, nil)
	d.reconcile(ctx)
	if len(domainRulesOf(sys)) != 1 {
		t.Fatal("route back after kill switch")
	}

	// removing the route forgets its addresses
	if err := d.RemoveRoute("google"); err != nil {
		t.Fatal(err)
	}
	d.reconcile(ctx)
	if got := domainRulesOf(sys); len(got) != 0 {
		t.Fatalf("after remove: %v", got)
	}
}

func TestEndpointNeverEmpty(t *testing.T) {
	d, _, _ := setup(t)
	if err := d.Set("endpoint", " "); err == nil {
		t.Fatal("empty endpoint accepted")
	}
	if d.Config().Server.Endpoint != "203.0.113.1" {
		t.Fatal("endpoint changed")
	}
	if err := d.SetMany([][2]string{{"language", "de"}, {"endpoint", ""}}); err == nil || d.Config().Web.Language == "de" {
		t.Fatal("settings save with empty endpoint must fail as a whole")
	}
}

func TestCertFollowsHostnames(t *testing.T) {
	d, _, _ := setup(t)
	if err := d.EnsureTLS(); err != nil {
		t.Fatal(err)
	}
	if err := d.Set("hostnames", "v.witch, wgx.netbird.cloud"); err != nil {
		t.Fatal(err)
	}
	cert, err := d.Certificate()
	if err != nil || cert.VerifyHostname("wgx.netbird.cloud") != nil || cert.VerifyHostname("203.0.113.1") != nil {
		t.Fatalf("certificate does not cover the new name: %v", err)
	}
}

func TestIngressOptions(t *testing.T) {
	in := config.Ingress{AWG: ingress.GenerateParams(ingress.NewRand())}
	on, off := true, false
	IngressOptions{Strict: &on, ContentPadding: &off, DisableCookies: &off}.apply(&in)
	a := in.AWG
	if !a.Strict() || a.ContentPadding != "" || a.DisableCookies {
		t.Fatalf("%+v", a)
	}
	IngressOptions{Strict: &on}.apply(&in) // idempotent: same key
	if in.AWG.HeaderProtectionKey != a.HeaderProtectionKey {
		t.Fatal("key changed")
	}
	IngressOptions{Strict: &off}.apply(&in)
	if in.AWG.Strict() {
		t.Fatal("still strict")
	}
}

func TestIngresses(t *testing.T) {
	d, sys, _ := setup(t)
	ctx := context.Background()
	on := true
	if err := d.AddIngress("strict", IngressOptions{Strict: &on, Isolated: &on}); err != nil {
		t.Fatal(err)
	}
	if err := d.AddIngress("open", IngressOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := d.AddIngress("open", IngressOptions{}); err == nil {
		t.Fatal("duplicate name accepted")
	}
	c := d.Config()
	s, _ := c.Ingress("strict")
	o, _ := c.Ingress("open")
	if s.Interface != "awg1" || s.ListenPort != config.DefaultListenPort+1 || !s.AWG.Strict() || !s.Isolated {
		t.Fatalf("strict ingress: %+v", s)
	}
	if o.Interface != "awg2" || o.ListenPort != config.DefaultListenPort+2 {
		t.Fatalf("open ingress: %+v", o)
	}
	// only the non-isolated ingress may reach the admin UI
	if slices.Contains(c.Server.AdminInterfaces, "awg1") || !slices.Contains(c.Server.AdminInterfaces, "awg2") {
		t.Fatalf("admin interfaces: %v", c.Server.AdminInterfaces)
	}

	name := "strict"
	if _, err := d.AddClient("laptop", ClientOptions{Ingress: &name}); err != nil {
		t.Fatal(err)
	}
	if cl, _ := d.Config().Client("laptop"); !cl.AWG3 || cl.Ingress != "strict" {
		t.Fatalf("client on strict ingress: %+v", cl)
	}
	bad := "nope"
	if _, err := d.AddClient("x", ClientOptions{Ingress: &bad}); err == nil {
		t.Fatal("unknown ingress accepted")
	}
	d.reconcile(ctx)
	if len(sys.ingresses) != 3 || len(sys.peers["awg0"]) != 1 || len(sys.peers["awg1"]) != 1 || len(sys.peers["awg2"]) != 0 {
		t.Fatalf("ingresses %v, peers %v", sys.ingresses, sys.peers)
	}

	// admin access per ingress: switch it on for the isolated one, off for the open one
	off := false
	if err := d.SetIngress("strict", IngressOptions{Admin: &on}); err != nil {
		t.Fatal(err)
	}
	if err := d.SetIngress("open", IngressOptions{Admin: &off}); err != nil {
		t.Fatal(err)
	}
	if err := d.SetIngress("open", IngressOptions{Admin: &off}); err != nil { // idempotent
		t.Fatal(err)
	}
	if ai := d.Config().Server.AdminInterfaces; !slices.Contains(ai, "awg1") || slices.Contains(ai, "awg2") || !slices.Contains(ai, "awg0") {
		t.Fatalf("admin interfaces after toggles: %v", ai)
	}
	if err := d.AddIngress("quiet", IngressOptions{Admin: &off}); err != nil {
		t.Fatal(err)
	}
	if q, _ := d.Config().Ingress("quiet"); slices.Contains(d.Config().Server.AdminInterfaces, q.Interface) {
		t.Fatal("explicit admin off ignored on add")
	}
	if err := d.RemoveIngress("quiet"); err != nil {
		t.Fatal(err)
	}

	// in use: cannot be removed until the client moves
	if err := d.RemoveIngress("strict"); err == nil {
		t.Fatal("removed an ingress with clients")
	}
	def := config.DefaultIngress
	if err := d.UpdateClient("laptop", ClientOptions{Ingress: &def}); err != nil {
		t.Fatal(err)
	}
	if err := d.RemoveIngress("strict"); err != nil {
		t.Fatal(err)
	}
	if err := d.RemoveIngress("open"); err != nil {
		t.Fatal(err)
	}
	if ai := d.Config().Server.AdminInterfaces; slices.Contains(ai, "awg1") || slices.Contains(ai, "awg2") {
		t.Fatalf("admin interface of a removed ingress kept: %v", ai)
	}
	if err := d.RemoveIngress(config.DefaultIngress); err == nil {
		t.Fatal("removed the last ingress")
	}
	d.reconcile(ctx)
	if len(sys.ingresses) != 1 || len(sys.peers["awg0"]) != 2 {
		t.Fatalf("after removal: ingresses %v, peers %v", sys.ingresses, sys.peers)
	}
}

func TestRouteDomain(t *testing.T) {
	d, _, _ := setup(t)
	if err := d.SetRoute("google", "office", []string{"google.de", "google.com"}); err != nil {
		t.Fatal(err)
	}
	// joins a new route named after the egress and leaves the old one
	if err := d.RouteDomain("google.de", "home"); err != nil {
		t.Fatal(err)
	}
	if r, ok := d.Config().Route("home"); !ok || r.Egress != "home" || !slices.Equal(r.Domains, []string{"google.de"}) {
		t.Fatalf("new route: %+v", r)
	}
	if r, _ := d.Config().Route("google"); !slices.Equal(r.Domains, []string{"google.com"}) {
		t.Fatalf("old route keeps the rest: %v", r.Domains)
	}
	// joins the existing route of the egress; the emptied route goes away
	if err := d.RouteDomain("google.com", "home"); err != nil {
		t.Fatal(err)
	}
	if _, ok := d.Config().Route("google"); ok {
		t.Fatal("empty route kept")
	}
	if r, _ := d.Config().Route("home"); !slices.Equal(r.Domains, []string{"google.com", "google.de"}) {
		t.Fatalf("existing route: %v", r.Domains)
	}
	if err := d.RouteDomain("x.de", "nope"); err == nil {
		t.Fatal("unknown egress accepted")
	}
}

func TestNewClientsAWG3Default(t *testing.T) {
	d, _, _ := setup(t)
	on := true
	if err := d.SetIngress(config.DefaultIngress, IngressOptions{ContentPadding: &on, NewClientsAWG3: &on}); err != nil {
		t.Fatal(err)
	}
	conf, err := d.AddClient("a", ClientOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if cl, _ := d.Config().Client("a"); !cl.AWG3 || !strings.Contains(conf, "ContentPaddingAddition") {
		t.Fatalf("default not applied: %+v", cl)
	}
	off := false
	if _, err := d.AddClient("b", ClientOptions{AWG3: &off}); err != nil {
		t.Fatal(err)
	}
	if cl, _ := d.Config().Client("b"); cl.AWG3 {
		t.Fatal("opt-out ignored")
	}
	if err := d.SetIngress(config.DefaultIngress, IngressOptions{NewClientsAWG3: &off}); err != nil {
		t.Fatal(err)
	}
	if _, err := d.AddClient("c", ClientOptions{}); err != nil {
		t.Fatal(err)
	}
	if cl, _ := d.Config().Client("c"); cl.AWG3 {
		t.Fatal("default off ignored")
	}
}
