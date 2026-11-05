//go:build linux

package egress

import (
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/sseewald/vwitch/internal/config"
)

// Manager syncs kernel WireGuard interfaces named vwe<index>.
type Manager struct {
	wg      *wgctrl.Client
	applied map[string]Spec
}

// NewManager opens the WireGuard control client.
func NewManager() (*Manager, error) {
	c, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("wgctrl: %w", err)
	}
	return &Manager{wg: c, applied: map[string]Spec{}}, nil
}

// Sync creates/updates the given interfaces and removes stale vwe* links.
func (m *Manager) Sync(specs []Spec) error {
	var errs []error
	want := map[string]bool{}
	for _, s := range specs {
		want[s.Iface] = true
		if old, ok := m.applied[s.Iface]; ok && old == s && linkExists(s.Iface) {
			continue
		}
		if err := m.apply(s); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", s.Iface, err))
			delete(m.applied, s.Iface)
			continue
		}
		m.applied[s.Iface] = s
	}
	links, err := netlink.LinkList()
	if err != nil {
		return errors.Join(append(errs, err)...)
	}
	for _, l := range links {
		name := l.Attrs().Name
		if l.Type() == "wireguard" && strings.HasPrefix(name, config.EgressIfacePrefix) && !want[name] {
			if err := netlink.LinkDel(l); err != nil {
				errs = append(errs, fmt.Errorf("remove %s: %w", name, err))
			}
			delete(m.applied, name)
		}
	}
	return errors.Join(errs...)
}

func (m *Manager) apply(s Spec) error {
	link, err := netlink.LinkByName(s.Iface)
	if err != nil {
		wgLink := &netlink.Wireguard{LinkAttrs: netlink.LinkAttrs{Name: s.Iface, MTU: s.MTU}}
		if err := netlink.LinkAdd(wgLink); err != nil {
			return fmt.Errorf("create link (is the wireguard kernel module available?): %w", err)
		}
		if link, err = netlink.LinkByName(s.Iface); err != nil {
			return err
		}
	}
	if err := netlink.LinkSetMTU(link, s.MTU); err != nil {
		return err
	}
	addr := &netlink.Addr{IPNet: &net.IPNet{IP: net.IP(s.Address.AsSlice()), Mask: net.CIDRMask(32, 32)}}
	if err := netlink.AddrReplace(link, addr); err != nil {
		return err
	}
	priv, err := wgtypes.ParseKey(s.PrivateKey)
	if err != nil {
		return fmt.Errorf("private key: %w", err)
	}
	pub, err := wgtypes.ParseKey(s.PublicKey)
	if err != nil {
		return fmt.Errorf("public key: %w", err)
	}
	peer := wgtypes.PeerConfig{
		PublicKey:                   pub,
		ReplaceAllowedIPs:           true,
		AllowedIPs:                  []net.IPNet{{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)}},
		PersistentKeepaliveInterval: &s.Keepalive,
	}
	if s.Endpoint.IsValid() {
		peer.Endpoint = net.UDPAddrFromAddrPort(s.Endpoint)
	}
	if s.PresharedKey != "" {
		psk, err := wgtypes.ParseKey(s.PresharedKey)
		if err != nil {
			return fmt.Errorf("preshared key: %w", err)
		}
		peer.PresharedKey = &psk
	}
	if err := m.wg.ConfigureDevice(s.Iface, wgtypes.Config{PrivateKey: &priv, ReplacePeers: true, Peers: []wgtypes.PeerConfig{peer}}); err != nil {
		return err
	}
	return netlink.LinkSetUp(link)
}

// Stats returns the counters of the egress peer.
func (m *Manager) Stats(iface string) (Stats, error) {
	d, err := m.wg.Device(iface)
	if err != nil {
		return Stats{}, err
	}
	if len(d.Peers) == 0 {
		return Stats{}, errors.New("no peer")
	}
	p := d.Peers[0]
	st := Stats{LastHandshake: p.LastHandshakeTime, RxBytes: p.ReceiveBytes, TxBytes: p.TransmitBytes, ListenPort: d.ListenPort}
	if p.Endpoint != nil {
		st.Endpoint = p.Endpoint.String()
	}
	return st, nil
}

// Close releases the control client.
func (m *Manager) Close() error { return m.wg.Close() }

func linkExists(name string) bool {
	_, err := netlink.LinkByName(name)
	return err == nil
}
