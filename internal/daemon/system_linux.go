//go:build linux

package daemon

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"time"

	"github.com/sseewald/vwitch/internal/config"
	"github.com/sseewald/vwitch/internal/egress"
	"github.com/sseewald/vwitch/internal/exposure"
	"github.com/sseewald/vwitch/internal/firewall"
	"github.com/sseewald/vwitch/internal/health"
	"github.com/sseewald/vwitch/internal/ingress"
	"github.com/sseewald/vwitch/internal/routing"
	"github.com/sseewald/vwitch/internal/sysctl"
)

type linuxSystem struct {
	ingress ingress.Backend
	egress  *egress.Manager
}

// NewSystem returns the kernel backed system.
func NewSystem(log *slog.Logger) (System, error) {
	m, err := egress.NewManager()
	if err != nil {
		return nil, err
	}
	return &linuxSystem{ingress: ingress.NewUserspace(log), egress: m}, nil
}

func (s *linuxSystem) Prepare() error { return sysctl.Apply("/proc/sys", sysctl.Required) }

func (s *linuxSystem) IngressUp(sp ingress.Spec) error                  { return s.ingress.Up(sp) }
func (s *linuxSystem) SyncPeers(p []ingress.Peer) error                 { return s.ingress.SyncPeers(p) }
func (s *linuxSystem) PeerStats() (map[string]ingress.PeerStats, error) { return s.ingress.Stats() }

func (s *linuxSystem) SyncEgresses(sp []egress.Spec) error            { return s.egress.Sync(sp) }
func (s *linuxSystem) EgressStats(iface string) (egress.Stats, error) { return s.egress.Stats(iface) }
func (s *linuxSystem) Probe(ctx context.Context, iface string, t config.Target, timeout time.Duration) (time.Duration, error) {
	return health.Probe(ctx, iface, t, timeout)
}

func (s *linuxSystem) ApplyRouting(p routing.Plan) error     { return routing.Apply(p) }
func (s *linuxSystem) FlushConntrack(a []netip.Addr) error   { return routing.FlushConntrack(a) }
func (s *linuxSystem) ApplyFirewall(r []firewall.Rule) error { return firewall.Apply(r) }

func (s *linuxSystem) Listening() ([]exposure.Socket, error) { return exposure.Listening() }

func (s *linuxSystem) InterfaceAddrs(name string) []netip.Addr {
	i, err := net.InterfaceByName(name)
	if err != nil {
		return nil
	}
	addrs, _ := i.Addrs()
	var out []netip.Addr
	for _, a := range addrs {
		if p, err := netip.ParsePrefix(a.String()); err == nil {
			out = append(out, p.Addr())
		}
	}
	return out
}

func (s *linuxSystem) InterfaceUp(name string) bool {
	i, err := net.InterfaceByName(name)
	if err != nil || i.Flags&net.FlagUp == 0 {
		return false
	}
	addrs, _ := i.Addrs()
	return len(addrs) > 0
}

func (s *linuxSystem) Close() error {
	return errors.Join(s.ingress.Close(), s.egress.Close())
}
