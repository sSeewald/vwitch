package dns

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func answer(t *testing.T, rc dnsmessage.RCode, ttl uint32) []byte {
	t.Helper()
	q := dnsmessage.Question{Name: dnsmessage.MustNewName("example.org."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 7, Response: true, RCode: rc})
	_ = b.StartQuestions()
	_ = b.Question(q)
	if rc == dnsmessage.RCodeSuccess {
		_ = b.StartAnswers()
		_ = b.AResource(dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: ttl}, dnsmessage.AResource{A: [4]byte{192, 0, 2, 1}})
	}
	out, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestCache(t *testing.T) {
	c := newCache()
	now := time.Unix(1_000_000, 0)
	c.now = func() time.Time { return now }
	q := dnsmessage.Question{Name: dnsmessage.MustNewName("Example.ORG."), Type: dnsmessage.TypeA}
	home, office := cacheKeyOf(q, "vwe1"), cacheKeyOf(q, "vwe2")

	c.put(home, answer(t, dnsmessage.RCodeSuccess, 300))
	now = now.Add(100 * time.Second)
	h, ans := parse(t, c.get(home, 99))
	if h.ID != 99 || len(ans) != 1 || ans[0].Header.TTL != 200 {
		t.Fatalf("id %d ttl %v", h.ID, ans)
	}
	if c.get(office, 1) != nil {
		t.Fatal("another egress must not share the answer")
	}
	now = now.Add(200 * time.Second)
	if c.get(home, 1) != nil {
		t.Fatal("expired answer served")
	}

	c.put(home, answer(t, dnsmessage.RCodeNameError, 0))
	if h, _ := parse(t, c.get(home, 1)); h.RCode != dnsmessage.RCodeNameError {
		t.Fatal("NXDOMAIN not cached")
	}
	c.put(office, answer(t, dnsmessage.RCodeServerFailure, 0))
	if c.get(office, 1) != nil {
		t.Fatal("SERVFAIL cached")
	}
}

func TestForwarderUsesCache(t *testing.T) {
	var asked atomic.Int32
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
			asked.Add(1)
			var m dnsmessage.Message
			_ = m.Unpack(buf[:n])
			resp := answer(t, dnsmessage.RCodeSuccess, 300)
			resp[0], resp[1] = buf[0], buf[1] // echo the ID
			_, _ = pc.WriteTo(resp, from)
		}
	}()
	learned := 0
	f := &Forwarder{
		Listen:   netip.MustParseAddr("10.8.0.1"),
		Upstream: pc.LocalAddr().(*net.UDPAddr).AddrPort(),
		Names:    func() []string { return nil },
		Route:    func(netip.Addr, string) (string, bool) { return "", true },
		Learn:    func(string, []netip.Addr, time.Duration) { learned++ },
		Timeout:  time.Second,
		Log:      slog.Default(),
	}
	client := netip.MustParseAddr("10.8.0.2")
	for range 3 {
		if h, ans := parse(t, f.handle(context.Background(), query(t, "example.org.", dnsmessage.TypeA), client, "udp")); h.ID != 42 || len(ans) != 1 {
			t.Fatalf("answer %v %v", h, ans)
		}
	}
	if asked.Load() != 1 {
		t.Fatalf("upstream asked %d times, want 1", asked.Load())
	}
	if learned != 3 {
		t.Fatalf("learn on cache hits: %d", learned)
	}
}
