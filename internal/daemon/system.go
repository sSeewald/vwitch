package daemon

import (
	"context"
	"net/netip"
	"time"

	"github.com/sseewald/vwitch/internal/config"
	"github.com/sseewald/vwitch/internal/egress"
	"github.com/sseewald/vwitch/internal/exposure"
	"github.com/sseewald/vwitch/internal/firewall"
	"github.com/sseewald/vwitch/internal/ingress"
	"github.com/sseewald/vwitch/internal/nflog"
	"github.com/sseewald/vwitch/internal/routing"
)

// System is everything the daemon does to the host. The linux
// implementation talks to the kernel; tests use a fake.
type System interface {
	Prepare() error // sysctl etc.

	// IngressUp creates or updates the ingress interface spec.Name.
	IngressUp(ingress.Spec) error
	IngressDown(iface string) error
	SyncPeers(iface string, peers []ingress.Peer) error
	PeerStats() (map[string]ingress.PeerStats, error) // of all ingresses

	SyncEgresses([]egress.Spec) error
	EgressStats(iface string) (egress.Stats, error)
	Probe(ctx context.Context, iface string, t config.Target, timeout time.Duration) (time.Duration, error)

	ApplyRouting(routing.Plan) error
	FlushConntrack([]netip.Addr) error
	ApplyFirewall([]firewall.Rule) error
	ApplyBlock([]firewall.Set, []firewall.Rule) error
	// ListenBlocked delivers logged block hits until ctx ends.
	ListenBlocked(ctx context.Context, fn func(nflog.Hit)) error

	InterfaceUp(name string) bool
	InterfaceAddrs(name string) []netip.Addr
	Listening() ([]exposure.Socket, error)
	Close() error
}
