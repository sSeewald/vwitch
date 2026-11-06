package activity

import (
	"net/netip"
	"testing"
	"time"
)

func TestDomains(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	d := NewDomains(time.Hour, 3)
	d.Seen("phone", "rr1.googlevideo.com", false, now)
	d.Seen("phone", "rr2.googlevideo.com", false, now)
	d.Seen("laptop", "rr1.googlevideo.com", false, now)
	d.Seen("laptop", "ads.example.co.uk", true, now)

	l := d.List("", now)
	if len(l) != 2 || l[0].Domain != "googlevideo.com" || l[0].Queries != 3 || len(l[0].Clients) != 2 ||
		l[0].Names[0] != "rr1.googlevideo.com" || len(l[0].Names) != 2 {
		t.Fatalf("%+v", l)
	}
	if l[1].Domain != "example.co.uk" || l[1].Blocked != 1 {
		t.Fatalf("public suffix grouping: %+v", l[1])
	}
	if p := d.List("phone", now); len(p) != 1 || p[0].Queries != 2 {
		t.Fatalf("per client: %+v", p)
	}
	// the oldest entry makes room when full
	d.Seen("phone", "a.test", false, now.Add(time.Minute))
	d.Seen("phone", "b.test", false, now.Add(2*time.Minute))
	if l := d.List("", now.Add(2*time.Minute)); len(l) != 3 {
		t.Fatalf("max: %d", len(l))
	}
	if l := d.List("", now.Add(3*time.Hour)); len(l) != 0 {
		t.Fatal("not expired")
	}
}

func TestResolvedAndRegionBlocked(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	r := NewResolved(time.Hour, 3)
	a, b := netip.MustParseAddr("5.8.0.1"), netip.MustParseAddr("5.8.0.2")
	r.Add("www.mail.ru", []netip.Addr{a, b}, now)
	if r.Name(a, now) != "www.mail.ru" || r.Name(netip.MustParseAddr("1.1.1.1"), now) != "" {
		t.Fatal("lookup")
	}
	if r.Name(a, now.Add(2*time.Hour)) != "" {
		t.Fatal("expired name returned")
	}
	r.Add("x.test", []netip.Addr{netip.MustParseAddr("1.0.0.1"), netip.MustParseAddr("1.0.0.2")}, now.Add(2*time.Hour))
	if len(r.m) > 3 {
		t.Fatalf("over max: %d", len(r.m))
	}

	d := NewDomains(24*time.Hour, 10)
	d.Seen("phone", "www.mail.ru", false, now)
	d.RegionBlocked("img.mail.ru", "RU", now)
	d.RegionBlocked("unknown.test", "CN", now) // never looked up: ignored
	l := d.List("", now)
	if len(l) != 1 || l[0].Country != "RU" {
		t.Fatalf("%+v", l)
	}
}
