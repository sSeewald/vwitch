package dns

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
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

// fakeUpstream answers every query with NXDOMAIN.
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
			_, _ = pc.WriteTo(reply(h, q, dnsmessage.RCodeNameError, nil), from)
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
		Route:    func(c netip.Addr) (string, bool) { return "", c != blocked },
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
