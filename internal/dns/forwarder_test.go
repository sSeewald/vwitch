package dns

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func query(t *testing.T, name string, typ dnsmessage.Type) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 42, RecursionDesired: true})
	_ = b.StartQuestions()
	_ = b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name), Type: typ, Class: dnsmessage.ClassINET})
	out, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func parse(t *testing.T, b []byte) (dnsmessage.Header, []dnsmessage.Resource) {
	t.Helper()
	var m dnsmessage.Message
	if err := m.Unpack(b); err != nil {
		t.Fatal(err)
	}
	return m.Header, m.Answers
}

// fakeUpstream answers google.de with a CNAME and two A records, everything
// else with NXDOMAIN.
func fakeUpstream(t *testing.T) netip.AddrPort {
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 512)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			var p dnsmessage.Parser
			h, _ := p.Start(buf[:n])
			q, _ := p.Question()
			if !strings.EqualFold(q.Name.String(), "google.de.") {
				_, _ = pc.WriteTo(reply(h, q, dnsmessage.RCodeNameError, nil), from)
				continue
			}
			b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, Response: true, RecursionAvailable: true})
			_ = b.StartQuestions()
			_ = b.Question(q)
			_ = b.StartAnswers()
			cname := dnsmessage.MustNewName("www.google.de.")
			_ = b.CNAMEResource(dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: 300}, dnsmessage.CNAMEResource{CNAME: cname})
			_ = b.AResource(dnsmessage.ResourceHeader{Name: cname, Class: dnsmessage.ClassINET, TTL: 120}, dnsmessage.AResource{A: [4]byte{192, 0, 2, 1}})
			_ = b.AResource(dnsmessage.ResourceHeader{Name: cname, Class: dnsmessage.ClassINET, TTL: 60}, dnsmessage.AResource{A: [4]byte{192, 0, 2, 2}})
			out, _ := b.Finish()
			_, _ = pc.WriteTo(out, from)
		}
	}()
	return pc.LocalAddr().(*net.UDPAddr).AddrPort()
}

func TestForwarder(t *testing.T) {
	blocked := netip.MustParseAddr("10.8.0.9")
	f := &Forwarder{
		Listen:   netip.MustParseAddr("10.8.0.1"),
		Upstream: fakeUpstream(t),
		Names:    func() []string { return []string{"vwitch.internal", "v.witch"} },
		Route:    func(c netip.Addr, _ string) (string, bool) { return "", c != blocked },
		Timeout:  time.Second,
		Log:      slog.Default(),
	}
	ctx := context.Background()
	client := netip.MustParseAddr("10.8.0.2")

	h, ans := parse(t, f.handle(ctx, query(t, "VWitch.Internal.", dnsmessage.TypeA), client, "udp"))
	if h.RCode != dnsmessage.RCodeSuccess || len(ans) != 1 || ans[0].Body.(*dnsmessage.AResource).A != [4]byte{10, 8, 0, 1} {
		t.Fatalf("local A: %v %v", h, ans)
	}
	h, ans = parse(t, f.handle(ctx, query(t, "v.witch.", dnsmessage.TypeAAAA), client, "udp"))
	if h.RCode != dnsmessage.RCodeSuccess || len(ans) != 0 {
		t.Fatal("local AAAA should be NODATA")
	}
	h, _ = parse(t, f.handle(ctx, query(t, "example.org.", dnsmessage.TypeA), client, "udp"))
	if h.RCode != dnsmessage.RCodeNameError || h.ID != 42 {
		t.Fatalf("forwarded: %v", h)
	}
	h, _ = parse(t, f.handle(ctx, query(t, "example.org.", dnsmessage.TypeA), blocked, "udp"))
	if h.RCode != dnsmessage.RCodeRefused {
		t.Fatalf("blocked client got %v", h.RCode)
	}
}

func TestForwarderLearns(t *testing.T) {
	var routed, learned string
	var addrs []netip.Addr
	var ttl time.Duration
	f := &Forwarder{
		Listen:   netip.MustParseAddr("10.8.0.1"),
		Upstream: fakeUpstream(t),
		Names:    func() []string { return nil },
		Route:    func(_ netip.Addr, name string) (string, bool) { routed = name; return "", true },
		Learn:    func(name string, a []netip.Addr, tt time.Duration) { learned, addrs, ttl = name, a, tt },
		Timeout:  time.Second,
		Log:      slog.Default(),
	}
	client := netip.MustParseAddr("10.8.0.2")
	h, _ := parse(t, f.handle(context.Background(), query(t, "Google.DE.", dnsmessage.TypeA), client, "udp"))
	if h.RCode != dnsmessage.RCodeSuccess {
		t.Fatalf("rcode %v", h.RCode)
	}
	if routed != "google.de" || learned != "google.de" || ttl != time.Minute ||
		len(addrs) != 2 || addrs[0] != netip.MustParseAddr("192.0.2.1") {
		t.Fatalf("routed %q learned %q %v ttl %v", routed, learned, addrs, ttl)
	}
	learned = ""
	parse(t, f.handle(context.Background(), query(t, "example.org.", dnsmessage.TypeA), client, "udp"))
	if learned != "" {
		t.Fatal("NXDOMAIN must not learn")
	}
}

func TestForwarderBlocks(t *testing.T) {
	var seen []string
	routed := false
	f := &Forwarder{
		Listen: netip.MustParseAddr("10.8.0.1"),
		Names:  func() []string { return nil },
		Route:  func(netip.Addr, string) (string, bool) { routed = true; return "", false },
		Block: func(_ netip.Addr, name string) (string, bool) {
			return "custom", name == "ads.example"
		},
		Seen: func(_ netip.Addr, name, source string) { seen = append(seen, name+"/"+source) },
		Log:  slog.Default(),
	}
	client := netip.MustParseAddr("10.8.0.2")
	h, ans := parse(t, f.handle(context.Background(), query(t, "ADS.example.", dnsmessage.TypeA), client, "udp"))
	if h.RCode != dnsmessage.RCodeSuccess || len(ans) != 1 || ans[0].Body.(*dnsmessage.AResource).A != [4]byte{} {
		t.Fatalf("blocked A: %v %v", h, ans)
	}
	if h, ans := parse(t, f.handle(context.Background(), query(t, "ads.example.", dnsmessage.TypeAAAA), client, "udp")); h.RCode != dnsmessage.RCodeSuccess || len(ans) != 0 {
		t.Fatal("blocked AAAA must be empty")
	}
	if routed {
		t.Fatal("a blocked name must not be forwarded")
	}
	f.handle(context.Background(), query(t, "ok.example.", dnsmessage.TypeA), client, "udp")
	if len(seen) != 2 || seen[0] != "ads.example/custom" || seen[1] != "ok.example/" {
		t.Fatalf("seen %v (only A lookups count)", seen)
	}
}

func TestForwarderDropsRebinding(t *testing.T) {
	learned := false
	f := &Forwarder{
		Listen:   netip.MustParseAddr("10.8.0.1"),
		Upstream: fakeUpstream(t),
		Names:    func() []string { return nil },
		Route:    func(netip.Addr, string) (string, bool) { return "", true },
		Learn:    func(string, []netip.Addr, time.Duration) { learned = true },
		Timeout:  time.Second,
		Log:      slog.Default(),
	}
	client := netip.MustParseAddr("10.8.0.2")
	// the upstream answer (192.0.2.1, .2) points into the protected net
	f.Protect = netip.MustParsePrefix("192.0.2.0/30")
	h, ans := parse(t, f.handle(context.Background(), query(t, "google.de.", dnsmessage.TypeA), client, "udp"))
	if h.RCode != dnsmessage.RCodeSuccess || len(ans) != 0 || learned {
		t.Fatalf("rebinding answer passed: %v %v learned=%v", h, ans, learned)
	}
	// other addresses, private or not, pass (e.g. a LAN behind an egress)
	f.Protect = netip.MustParsePrefix("10.8.0.0/24")
	if _, ans = parse(t, f.handle(context.Background(), query(t, "google.de.", dnsmessage.TypeA), client, "udp")); len(ans) != 3 {
		t.Fatalf("normal answer: %v", ans)
	}
}
