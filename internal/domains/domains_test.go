package domains

import (
	"net/netip"
	"slices"
	"testing"
	"time"
)

func TestNormalize(t *testing.T) {
	for in, want := range map[string]string{
		"google.de":                     "google.de",
		" Google.DE. ":                  "google.de",
		"*.google.de":                   "google.de",
		".google.de":                    "google.de",
		"https://www.google.de/search?": "www.google.de",
		"http://example.org:8080/x":     "example.org",
		"de":                            "de",
	} {
		got, err := Normalize(in)
		if err != nil || got != want {
			t.Errorf("Normalize(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "*.", "exa mple.org", "-a.org", "a..org", "1.2.3.4", "ä.de"} {
		if _, err := Normalize(bad); err == nil {
			t.Errorf("Normalize(%q) accepted", bad)
		}
	}
}

func TestMatchMostSpecific(t *testing.T) {
	routes := []Route{
		{Name: "google", Domains: []string{"google.com", "google.de"}},
		{Name: "mail", Domains: []string{"mail.google.com"}},
		{Name: "german", Domains: []string{"de"}},
	}
	for name, want := range map[string]string{
		"google.com.":          "google",
		"WWW.google.com":       "google",
		"mail.google.com":      "mail",
		"a.mail.google.com":    "mail",
		"www.google.de":        "google",
		"spiegel.de":           "german",
		"notgoogle.com":        "",
		"google.com.evil.test": "",
	} {
		got, ok := Match(routes, name)
		if got != want || ok != (want != "") {
			t.Errorf("Match(%q) = %q, %v; want %q", name, got, ok, want)
		}
	}
}

func TestCache(t *testing.T) {
	var c Cache
	now := time.Unix(1_000_000, 0)
	a, b := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")
	v6 := netip.MustParseAddr("2001:db8::1")

	if !c.Learn("google", []netip.Addr{a, v6}, 30*time.Second, now) {
		t.Fatal("new address must report a change")
	}
	if c.Learn("google", []netip.Addr{a}, 30*time.Second, now.Add(time.Minute)) {
		t.Fatal("refresh is no change")
	}
	if !c.Learn("other", []netip.Addr{a}, time.Hour, now) {
		t.Fatal("moving to another route is a change")
	}
	c.Learn("google", []netip.Addr{b}, 0, now)

	got := c.Active(now)
	if !slices.Equal(got["other"], []netip.Addr{a}) || !slices.Equal(got["google"], []netip.Addr{b}) {
		t.Fatalf("active %v (IPv6 must be ignored)", got)
	}
	// short TTLs are raised to MinTTL
	if got := c.Active(now.Add(MinTTL - time.Second)); len(got["google"]) != 1 {
		t.Fatal("expired before MinTTL")
	}
	if got := c.Active(now.Add(MinTTL + time.Second)); len(got) != 0 {
		t.Fatalf("not expired: %v", got)
	}

	c.Learn("google", []netip.Addr{a}, 0, now)
	c.Forget(func(r string) bool { return r != "google" })
	if len(c.Active(now)) != 0 {
		t.Fatal("forget")
	}
}
