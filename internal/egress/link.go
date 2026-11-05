package egress

import (
	"net/netip"
	"time"

	"github.com/sseewald/vwitch/internal/config"
)

// Spec is the desired kernel state of one egress interface.
type Spec struct {
	Iface        string
	MTU          int
	Address      netip.Addr
	PrivateKey   string
	PublicKey    string
	PresharedKey string
	Endpoint     netip.AddrPort // resolved
	Keepalive    time.Duration
}

// Stats are runtime counters of an egress peer.
type Stats struct {
	LastHandshake time.Time
	RxBytes       int64
	TxBytes       int64
	Endpoint      string
	ListenPort    int // local UDP port of the tunnel
}

// SpecFor builds the spec of an egress with an already resolved endpoint.
func SpecFor(e config.Egress, serverMTU int, ep netip.AddrPort) Spec {
	mtu := e.MTU
	if mtu == 0 {
		mtu = serverMTU + 80 // egress carries client packets plus our own overhead
		mtu = min(mtu, 1420)
	}
	return Spec{
		Iface: e.Iface(), MTU: mtu, Address: e.Address,
		PrivateKey: e.PrivateKey, PublicKey: e.PublicKey, PresharedKey: e.PresharedKey,
		Endpoint: ep, Keepalive: time.Duration(e.Keepalive) * time.Second,
	}
}
