package egress

import (
	"net/netip"
	"testing"
)

func TestImport(t *testing.T) {
	e, err := Import("home", `[Interface]
PrivateKey = cHJpdg==
Address = fd00::2/64, 192.168.1.201/24
DNS = 192.168.1.1
[Peer]
PublicKey = cHVi
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = [2001:db8::1]:51820
`)
	if err != nil {
		t.Fatal(err)
	}
	if e.Address != netip.MustParseAddr("192.168.1.201") || e.Endpoint != "[2001:db8::1]:51820" || !e.Enabled {
		t.Fatalf("%+v", e)
	}
}

func TestImportRejects(t *testing.T) {
	if _, err := Import("x", "[Interface]\nPrivateKey = a\nAddress = fd00::2/64\n[Peer]\nPublicKey = b\nEndpoint = h:1\n"); err == nil {
		t.Fatal("IPv6-only accepted")
	}
	if _, err := Import("x", "[Interface]\nPrivateKey = a\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = b\n"); err == nil {
		t.Fatal("missing endpoint accepted")
	}
}
