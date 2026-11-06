package config

import (
	"net/netip"
	"strings"
	"testing"
)

func validConfig() *Config {
	c := New()
	c.Server.PrivateKey = "x"
	c.Server.AWG = AWGParams{Jc: 4, Jmin: 40, Jmax: 200, S1: 10, S2: 20, S3: 5, S4: 6,
		H1: "100-200", H2: "300-400", H3: "500-600", H4: "700-800"}
	c.Egresses = []Egress{{Name: "home", Index: 1, Enabled: true, Priority: 10,
		Endpoint: "home.example.org:51820", Address: netip.MustParseAddr("192.168.1.201"),
		PrivateKey: "a", PublicKey: "b"}}
	c.ApplyDefaults()
	return c
}

func TestRoundTrip(t *testing.T) {
	c := validConfig()
	data, err := c.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	got, err := Parse(data)
	if err != nil {
		t.Fatalf("parse: %v\n%s", err, data)
	}
	if got.Server.Address != c.Server.Address || got.Health.Interval != c.Health.Interval ||
		got.Egresses[0].Address != c.Egresses[0].Address {
		t.Fatalf("round trip mismatch:\n%s", data)
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name string
		mod  func(*Config)
		want string
	}{
		{"ok", func(*Config) {}, ""},
		{"lan resolver", func(c *Config) { c.DNS.Resolver = netip.MustParseAddr("192.168.178.1") }, "LAN"},
		{"ask needs direct", func(c *Config) { c.Selection.Offline = OfflineAsk }, "allow_direct"},
		{"overlapping headers", func(c *Config) { c.Server.AWG.H2 = "150-250" }, "overlaps"},
		{"s1+56", func(c *Config) { c.Server.AWG.S2 = 66 }, "s1+56"},
		{"fixed unknown", func(c *Config) {
			c.Selection.Strategy = StrategyFixed
			c.Selection.Fixed = "nope"
		}, "unknown egress"},
		{"bad endpoint", func(c *Config) { c.Egresses[0].Endpoint = "nohost" }, "endpoint"},
		{"dup client addr", func(c *Config) {
			a := netip.MustParseAddr("10.8.0.2")
			c.Clients = []Client{{Name: "a", Address: a, PublicKey: "k"}, {Name: "b", Address: a, PublicKey: "k"}}
		}, "not unique"},
		{"route ok", func(c *Config) {
			c.Routes = []Route{{Name: "google", Egress: "home", Domains: []string{"google.com", "google.de"}},
				{Name: "mail", Egress: "home", Domains: []string{"mail.google.com"}}}
		}, ""},
		{"route unknown egress", func(c *Config) {
			c.Routes = []Route{{Name: "g", Egress: "nope", Domains: []string{"google.de"}}}
		}, "unknown egress"},
		{"route domain in two routes", func(c *Config) {
			c.Routes = []Route{{Name: "a", Egress: "home", Domains: []string{"google.de"}},
				{Name: "b", Egress: "home", Domains: []string{"google.de"}}}
		}, `already in route "a"`},
		{"route not normalized", func(c *Config) {
			c.Routes = []Route{{Name: "g", Egress: "home", Domains: []string{"*.Google.de"}}}
		}, "invalid domain"},
		{"route empty", func(c *Config) { c.Routes = []Route{{Name: "g", Egress: "home"}} }, "no domains"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := validConfig()
			tt.mod(c)
			err := c.Validate()
			if tt.want == "" {
				if err != nil {
					t.Fatalf("unexpected: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("want error containing %q, got %v", tt.want, err)
			}
		})
	}
}

func TestNextClientAddress(t *testing.T) {
	c := validConfig()
	c.Clients = []Client{{Name: "a", Address: netip.MustParseAddr("10.8.0.2")}}
	a, err := c.NextClientAddress()
	if err != nil || a != netip.MustParseAddr("10.8.0.3") {
		t.Fatalf("got %v %v", a, err)
	}
}

func TestSetOrder(t *testing.T) {
	c := validConfig()
	c.Egresses = append(c.Egresses,
		Egress{Name: "b", Priority: 20}, Egress{Name: "c", Priority: 30})
	if err := c.SetOrder([]string{"c"}); err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range c.SortedEgresses() {
		names = append(names, e.Name)
	}
	if strings.Join(names, ",") != "c,home,b" {
		t.Fatalf("order %v", names)
	}
}

func TestStoreUpdateRejectsInvalid(t *testing.T) {
	path := t.TempDir() + "/vwitch.yaml"
	s, err := Create(path, validConfig())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Update(func(c *Config) error { c.Server.MTU = 9000; return nil }); err == nil {
		t.Fatal("invalid update accepted")
	}
	if s.Get().Server.MTU != DefaultMTU {
		t.Fatal("invalid update persisted")
	}
	if _, err := Open(path); err != nil {
		t.Fatal(err)
	}
}
