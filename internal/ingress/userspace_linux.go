//go:build linux

package ingress

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// Userspace runs amneziawg-go inside the vwitch process.
type Userspace struct {
	log *slog.Logger

	mu   sync.Mutex
	dev  *device.Device
	spec Spec
}

// NewUserspace returns the embedded backend.
func NewUserspace(log *slog.Logger) *Userspace { return &Userspace{log: log} }

// Up creates the TUN device on first call and (re)applies interface settings.
func (u *Userspace) Up(s Spec) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.dev == nil {
		if err := u.create(s); err != nil {
			return err
		}
	} else if s.MTU != u.spec.MTU {
		return errors.New("mtu change requires a restart of vwitch")
	}
	uapi, err := interfaceUAPI(s)
	if err != nil {
		return err
	}
	if err := u.dev.IpcSet(uapi); err != nil {
		return fmt.Errorf("configure %s: %w", s.Name, err)
	}
	if err := u.address(s); err != nil {
		return err
	}
	u.spec = s
	return nil
}

func (u *Userspace) create(s Spec) error {
	t, err := tun.CreateTUN(s.Name, s.MTU)
	if err != nil {
		return fmt.Errorf("create tun %s: %w", s.Name, err)
	}
	logger := &device.Logger{
		Verbosef: func(string, ...any) {},
		Errorf:   func(f string, a ...any) { u.log.Error(fmt.Sprintf(f, a...), "iface", s.Name) },
	}
	u.dev = device.NewDevice(t, conn.NewDefaultBind(), logger)
	return nil
}

func (u *Userspace) address(s Spec) error {
	link, err := netlink.LinkByName(s.Name)
	if err != nil {
		return err
	}
	addr := &netlink.Addr{IPNet: &net.IPNet{IP: net.IP(s.Address.Addr().AsSlice()), Mask: net.CIDRMask(s.Address.Bits(), 32)}}
	if err := netlink.AddrReplace(link, addr); err != nil {
		return fmt.Errorf("address %s: %w", s.Address, err)
	}
	// drop stale addresses after an address change
	addrs, _ := netlink.AddrList(link, netlink.FAMILY_V4)
	for _, a := range addrs {
		if !a.IP.Equal(addr.IP) {
			_ = netlink.AddrDel(link, &a)
		}
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return err
	}
	return u.dev.Up()
}

// SyncPeers applies the desired peer set without disturbing unchanged peers.
func (u *Userspace) SyncPeers(peers []Peer) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.dev == nil {
		return errors.New("interface not up")
	}
	get, err := u.dev.IpcGet()
	if err != nil {
		return err
	}
	_, current, _ := parseStats(get)
	uapi, err := peersUAPI(current, peers)
	if err != nil {
		return err
	}
	if uapi != "" {
		if err := u.dev.IpcSet(uapi); err != nil {
			return err
		}
	}
	return u.peerRoutes(peers)
}

// peerRoutes routes each peer address to this interface. Ingresses share the
// client network, so the host routes decide which interface reaches a client.
func (u *Userspace) peerRoutes(peers []Peer) error {
	link, err := netlink.LinkByName(u.spec.Name)
	if err != nil {
		return err
	}
	want := map[netip.Addr]bool{}
	for _, p := range peers {
		want[p.Addr] = true
	}
	routes, err := netlink.RouteList(link, netlink.FAMILY_V4)
	if err != nil {
		return err
	}
	var errs []error
	for _, r := range routes {
		if r.Dst == nil || r.Table != unix.RT_TABLE_MAIN {
			continue
		}
		if ones, _ := r.Dst.Mask.Size(); ones != 32 {
			continue
		}
		a, _ := netip.AddrFromSlice(r.Dst.IP.To4())
		if want[a] {
			delete(want, a)
			continue
		}
		errs = append(errs, netlink.RouteDel(&r))
	}
	for a := range want {
		errs = append(errs, netlink.RouteReplace(&netlink.Route{LinkIndex: link.Attrs().Index, Scope: netlink.SCOPE_LINK,
			Dst: &net.IPNet{IP: net.IP(a.AsSlice()), Mask: net.CIDRMask(32, 32)}}))
	}
	return errors.Join(errs...)
}

// Stats returns per-peer counters.
func (u *Userspace) Stats() (map[string]PeerStats, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.dev == nil {
		return nil, errors.New("interface not up")
	}
	get, err := u.dev.IpcGet()
	if err != nil {
		return nil, err
	}
	st, _, err := parseStats(get)
	return st, err
}

// Close tears the device down.
func (u *Userspace) Close() error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.dev != nil {
		u.dev.Close()
		u.dev = nil
	}
	return nil
}
