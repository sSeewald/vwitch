// Package egress manages the WireGuard egress tunnels: import from wg-quick
// configs (pure) and the kernel interfaces (linux).
package egress

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/sseewald/vwitch/internal/config"
	"github.com/sseewald/vwitch/internal/wgconf"
)

// Import builds an egress from a standard wg-quick client config. Only the
// first IPv4 address is used (as /32); DNS, AllowedIPs and IPv6 are ignored
// because vwitch routes everything itself and enforces its own resolver.
func Import(name, text string) (config.Egress, error) {
	f, err := wgconf.Parse(text)
	if err != nil {
		return config.Egress{}, err
	}
	iface, peer := f.Interface(), f.Peer()
	e := config.Egress{
		Name:         name,
		Enabled:      true,
		PrivateKey:   iface.Get("PrivateKey"),
		PublicKey:    peer.Get("PublicKey"),
		PresharedKey: peer.Get("PresharedKey"),
		Endpoint:     peer.Get("Endpoint"),
		Resolve:      config.ResolveAny,
	}
	for _, a := range wgconf.List(iface.Get("Address")) {
		p, err := netip.ParsePrefix(a)
		if err != nil {
			addr, err2 := netip.ParseAddr(a)
			if err2 != nil {
				return config.Egress{}, fmt.Errorf("invalid Address %q", a)
			}
			p = netip.PrefixFrom(addr, addr.BitLen())
		}
		if p.Addr().Is4() {
			e.Address = p.Addr()
			break
		}
	}
	if !e.Address.IsValid() {
		return config.Egress{}, fmt.Errorf("config has no IPv4 Address")
	}
	if v := iface.Get("MTU"); v != "" {
		if e.MTU, err = strconv.Atoi(v); err != nil {
			return config.Egress{}, fmt.Errorf("invalid MTU %q", v)
		}
	}
	if v := peer.Get("PersistentKeepalive"); v != "" && !strings.EqualFold(v, "off") {
		if e.Keepalive, err = strconv.Atoi(v); err != nil {
			return config.Egress{}, fmt.Errorf("invalid PersistentKeepalive %q", v)
		}
	}
	if e.PrivateKey == "" || e.PublicKey == "" || e.Endpoint == "" {
		return config.Egress{}, fmt.Errorf("config needs PrivateKey, PublicKey and Endpoint")
	}
	if _, _, err := config.SplitEndpoint(e.Endpoint); err != nil {
		return config.Egress{}, err
	}
	return e, nil
}
