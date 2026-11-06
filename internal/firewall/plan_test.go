package firewall

import (
	"net/netip"
	"strings"
	"testing"
)

func testPlan() Plan {
	return Plan{
		AWGIface:      "awg0",
		ServerAddr:    netip.MustParseAddr("10.8.0.1"),
		ClientNet:     netip.MustParsePrefix("10.8.0.0/24"),
		PortalPort:    8080,
		EgressIfaces:  []string{"vwe1"},
		DirectClients: []netip.Addr{netip.MustParseAddr("10.8.0.3")},
		PortalClients: []netip.Addr{netip.MustParseAddr("10.8.0.4")},
		AdminPort:     8090,
		AdminIfaces:   []string{"lo", "wt0"},
	}
}

func TestRender(t *testing.T) {
	got := Render(testPlan().Rules())
	want := `table inet vwitch {
  chain input {
    iifname "lo" tcp dport 8090 accept
    iifname "wt0" tcp dport 8090 accept
    tcp dport 8090 drop
    iifname "awg0" ct state established,related accept
    iifname "awg0" tcp dport 8080 accept
    iifname "awg0" udp dport 53 accept
    iifname "awg0" tcp dport 53 accept
    iifname "awg0" meta l4proto icmp accept
    iifname "awg0" drop
  }
  chain forward {
    meta nfproto ipv6 iifname "awg0" drop
    oifname "awg0" ct state established,related accept
    iifname "awg0" oifname "awg0" accept
    iifname "awg0" oifname "vwe1" accept
    iifname "awg0" ip saddr 10.8.0.3 accept
    iifname "awg0" drop
    oifname "awg0" drop
  }
}
table ip vwitch_nat {
  chain prerouting {
    iifname "awg0" udp dport 53 dnat to 10.8.0.1
    iifname "awg0" tcp dport 53 dnat to 10.8.0.1
    iifname "awg0" ip saddr 10.8.0.4 tcp dport 80 dnat to 10.8.0.1:8080
  }
  chain postrouting {
    oifname != "awg0" ip saddr 10.8.0.0/24 masquerade
  }
}
`
	if got != want {
		t.Fatalf("got:\n%s", got)
	}
}

func TestNoLeakWithoutExits(t *testing.T) {
	// With no egress and no direct clients nothing from awg0 may be accepted
	// in forward except client-to-client traffic.
	p := testPlan()
	p.EgressIfaces, p.DirectClients, p.PortalClients = nil, nil, nil
	for _, r := range p.Rules() {
		if r.Chain == ChainForward && r.IIF == "awg0" && r.Verdict == Accept && r.OIF != "awg0" {
			t.Fatalf("leaky rule: %s", r)
		}
	}
}

func TestLockdownSSH(t *testing.T) {
	p := testPlan()
	p.LockdownSSH = true
	out := Render(p.Rules())
	if !strings.Contains(out, `iifname "wt0" tcp dport 22 accept`) || !strings.Contains(out, "tcp dport 22 drop") {
		t.Fatal(out)
	}
}

func TestAdminViaVPNButNoSSH(t *testing.T) {
	// awg0 as admin interface: clients reach the admin UI, never SSH
	p := testPlan()
	p.AdminIfaces = []string{"lo", "awg0", "wt0"}
	p.LockdownSSH = true
	out := Render(p.Rules())
	if !strings.Contains(out, `iifname "awg0" tcp dport 8090 accept`) {
		t.Fatal("admin not reachable via awg0:\n" + out)
	}
	if strings.Contains(out, `iifname "awg0" tcp dport 22 accept`) {
		t.Fatal("SSH open to VPN clients:\n" + out)
	}
	if strings.Index(out, `iifname "awg0" tcp dport 8090 accept`) > strings.Index(out, `iifname "awg0" drop`) {
		t.Fatal("admin accept must come before the awg0 drop:\n" + out)
	}
}
