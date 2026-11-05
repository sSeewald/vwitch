package dns

import (
	"context"
	"net/netip"
	"testing"

	"github.com/sseewald/vwitch/internal/config"
)

type fake map[string][]netip.Addr

func (f fake) LookupNetIP(_ context.Context, network, host string) ([]netip.Addr, error) {
	var out []netip.Addr
	for _, a := range f[host] {
		if network == "ip" || (network == "ip4") == a.Is4() {
			out = append(out, a)
		}
	}
	return out, nil
}

func TestResolveEndpoint(t *testing.T) {
	r := fake{"home.example": {netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1")}}
	ctx := context.Background()
	got, err := ResolveEndpoint(ctx, r, "home.example:51820", config.ResolveIPv6)
	if err != nil || got.String() != "[2001:db8::1]:51820" {
		t.Fatal(got, err)
	}
	got, _ = ResolveEndpoint(ctx, r, "home.example:51820", config.ResolveIPv4)
	if got.String() != "192.0.2.1:51820" {
		t.Fatal(got)
	}
	if _, err := ResolveEndpoint(ctx, r, "192.0.2.9:1", config.ResolveIPv6); err == nil {
		t.Fatal("v4 literal accepted for ipv6")
	}
}
