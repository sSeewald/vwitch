// Package dns resolves egress endpoints with an optional address family
// restriction (e.g. IPv6-only for DS-Lite lines with changing prefixes).
package dns

import (
	"context"
	"fmt"
	"net"
	"net/netip"

	"github.com/sseewald/vwitch/internal/config"
)

// Resolver looks up host addresses; *net.Resolver satisfies it.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// ResolveEndpoint turns "host:port" into an address, honouring the family.
// Literal IPs are returned as is (if they match the family).
func ResolveEndpoint(ctx context.Context, r Resolver, endpoint string, fam config.ResolveFamily) (netip.AddrPort, error) {
	host, port, err := config.SplitEndpoint(endpoint)
	if err != nil {
		return netip.AddrPort{}, err
	}
	network := "ip"
	switch fam {
	case config.ResolveIPv4:
		network = "ip4"
	case config.ResolveIPv6:
		network = "ip6"
	}
	if a, err := netip.ParseAddr(host); err == nil {
		if !matches(a, network) {
			return netip.AddrPort{}, fmt.Errorf("endpoint %s does not match resolve=%s", host, fam)
		}
		return netip.AddrPortFrom(a.Unmap(), port), nil
	}
	if r == nil {
		r = net.DefaultResolver
	}
	addrs, err := r.LookupNetIP(ctx, network, host)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("resolve %s: %w", host, err)
	}
	for _, a := range addrs {
		if a = a.Unmap(); matches(a, network) {
			return netip.AddrPortFrom(a, port), nil
		}
	}
	return netip.AddrPort{}, fmt.Errorf("resolve %s: no %s address", host, network)
}

func matches(a netip.Addr, network string) bool {
	switch network {
	case "ip4":
		return a.Is4()
	case "ip6":
		return a.Is6()
	}
	return true
}
