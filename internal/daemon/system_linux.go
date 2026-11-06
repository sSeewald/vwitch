//go:build linux

package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/sseewald/vwitch/internal/config"
	"github.com/sseewald/vwitch/internal/egress"
	"github.com/sseewald/vwitch/internal/exposure"
	"github.com/sseewald/vwitch/internal/firewall"
	"github.com/sseewald/vwitch/internal/health"
	"github.com/sseewald/vwitch/internal/ingress"
	"github.com/sseewald/vwitch/internal/nflog"
	"github.com/sseewald/vwitch/internal/routing"
	"github.com/sseewald/vwitch/internal/sysctl"
)

type linuxSystem struct {
	log    *slog.Logger
	egress *egress.Manager

	mu        sync.Mutex
	ingresses map[string]ingress.Backend // by interface
}

// NewSystem returns the kernel backed system.
func NewSystem(log *slog.Logger) (System, error) {
	m, err := egress.NewManager()
	if err != nil {
		return nil, err
	}
	return &linuxSystem{log: log, egress: m, ingresses: map[string]ingress.Backend{}}, nil
}

func (s *linuxSystem) Prepare() error { return sysctl.Apply("/proc/sys", sysctl.Required) }

func (s *linuxSystem) IngressUp(sp ingress.Spec) error {
	s.mu.Lock()
	b, ok := s.ingresses[sp.Name]
	if !ok {
		b = ingress.NewUserspace(s.log)
		s.ingresses[sp.Name] = b
	}
	s.mu.Unlock()
	return b.Up(sp)
}

func (s *linuxSystem) IngressDown(iface string) error {
	s.mu.Lock()
	b, ok := s.ingresses[iface]
	delete(s.ingresses, iface)
	s.mu.Unlock()
	if !ok {
		return nil
	}
	return b.Close()
}

func (s *linuxSystem) SyncPeers(iface string, p []ingress.Peer) error {
	s.mu.Lock()
	b, ok := s.ingresses[iface]
	s.mu.Unlock()
	if !ok {
		return fmt.Errorf("ingress %s not up", iface)
	}
	return b.SyncPeers(p)
}

func (s *linuxSystem) PeerStats() (map[string]ingress.PeerStats, error) {
	s.mu.Lock()
	bs := make([]ingress.Backend, 0, len(s.ingresses))
	for _, b := range s.ingresses {
		bs = append(bs, b)
	}
	s.mu.Unlock()
	out := map[string]ingress.PeerStats{}
	var errs []error
	for _, b := range bs {
		st, err := b.Stats()
		errs = append(errs, err)
		maps.Copy(out, st)
	}
	return out, errors.Join(errs...)
}

func (s *linuxSystem) SyncEgresses(sp []egress.Spec) error            { return s.egress.Sync(sp) }
func (s *linuxSystem) EgressStats(iface string) (egress.Stats, error) { return s.egress.Stats(iface) }
func (s *linuxSystem) Probe(ctx context.Context, iface string, t config.Target, timeout time.Duration) (time.Duration, error) {
	return health.Probe(ctx, iface, t, timeout)
}

func (s *linuxSystem) ApplyRouting(p routing.Plan) error     { return routing.Apply(p) }
func (s *linuxSystem) FlushConntrack(a []netip.Addr) error   { return routing.FlushConntrack(a) }
func (s *linuxSystem) ApplyFirewall(r []firewall.Rule) error { return firewall.Apply(r) }
func (s *linuxSystem) ApplyBlock(sets []firewall.Set, r []firewall.Rule) error {
	return firewall.ApplyBlock(sets, r)
}
func (s *linuxSystem) ListenBlocked(ctx context.Context, fn func(nflog.Hit)) error {
	return nflog.Listen(ctx, firewall.LogGroup, fn)
}

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
	s.mu.Lock()
	defer s.mu.Unlock()
	errs := []error{s.egress.Close()}
	for _, b := range s.ingresses {
		errs = append(errs, b.Close())
	}
	return errors.Join(errs...)
}
