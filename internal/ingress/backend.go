package ingress

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/sseewald/vwitch/internal/config"
)

// Spec is the desired server interface.
type Spec struct {
	Name       string
	Address    netip.Prefix
	ListenPort uint16
	MTU        int
	PrivateKey string // base64
	AWG        config.AWGParams
}

// Peer is a desired client peer.
type Peer struct {
	PublicKey    string // base64
	PresharedKey string // base64
	Addr         netip.Addr
}

// PeerStats are runtime counters of one peer.
type PeerStats struct {
	LastHandshake time.Time
	RxBytes       int64
	TxBytes       int64
	Endpoint      string
}

// Backend is an AmneziaWG implementation. The userspace backend embeds
// amneziawg-go; a kernel module backend can implement the same interface.
type Backend interface {
	Up(Spec) error
	SyncPeers([]Peer) error
	Stats() (map[string]PeerStats, error) // keyed by base64 public key
	Close() error
}

// Specs derives one interface spec per ingress.
func Specs(c *config.Config) []Spec {
	s := c.Server
	out := make([]Spec, len(c.Ingresses))
	for i, in := range c.Ingresses {
		out[i] = Spec{Name: in.Interface, Address: s.Address, ListenPort: in.ListenPort, MTU: s.MTU,
			PrivateKey: s.PrivateKey, AWG: in.AWG}
	}
	return out
}

// Peers returns the active clients of one ingress.
func Peers(c *config.Config, in config.Ingress, now time.Time) []Peer {
	var ps []Peer
	for _, cl := range c.Clients {
		if cl.Active(now) && c.ClientIngress(cl).Name == in.Name {
			ps = append(ps, Peer{PublicKey: cl.PublicKey, PresharedKey: cl.PresharedKey, Addr: cl.Address})
		}
	}
	return ps
}

// interfaceUAPI renders the interface part of a UAPI set operation.
func interfaceUAPI(s Spec) (string, error) {
	key, err := keyHex(s.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("private key: %w", err)
	}
	a := s.AWG
	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\nlisten_port=%d\n", key, s.ListenPort)
	fmt.Fprintf(&b, "jc=%d\njmin=%d\njmax=%d\ns1=%d\ns2=%d\ns3=%d\ns4=%d\n", a.Jc, a.Jmin, a.Jmax, a.S1, a.S2, a.S3, a.S4)
	fmt.Fprintf(&b, "h1=%s\nh2=%s\nh3=%s\nh4=%s\n", a.H1, a.H2, a.H3, a.H4)
	// AWG 3.1: always written, so switching a feature off resets the device
	hpk := strings.Repeat("0", 64) // all zero: header protection off
	if a.HeaderProtectionKey != "" {
		if hpk, err = keyHex(a.HeaderProtectionKey); err != nil {
			return "", fmt.Errorf("header protection key: %w", err)
		}
	}
	padding := a.ContentPadding
	if padding == "" {
		padding = "0" // off
	}
	fmt.Fprintf(&b, "header_protection_key=%s\ncontent_padding_addition=%s\nrandom_trailers=%t\ndisable_cookies=%t\n",
		hpk, padding, a.RandomTrailers, a.DisableCookies)
	return b.String(), nil
}

// peersUAPI renders a peer diff: removes unknown peers, upserts desired ones.
func peersUAPI(current []string, desired []Peer) (string, error) {
	want := map[string]bool{}
	var b strings.Builder
	for _, p := range desired {
		pk, err := keyHex(p.PublicKey)
		if err != nil {
			return "", fmt.Errorf("peer key: %w", err)
		}
		want[pk] = true
		fmt.Fprintf(&b, "public_key=%s\n", pk)
		if p.PresharedKey != "" {
			psk, err := keyHex(p.PresharedKey)
			if err != nil {
				return "", fmt.Errorf("preshared key: %w", err)
			}
			fmt.Fprintf(&b, "preshared_key=%s\n", psk)
		}
		fmt.Fprintf(&b, "replace_allowed_ips=true\nallowed_ip=%s/32\n", p.Addr)
	}
	for _, pk := range current {
		if !want[pk] {
			fmt.Fprintf(&b, "public_key=%s\nremove=true\n", pk)
		}
	}
	return b.String(), nil
}

// parseStats parses a UAPI get response.
func parseStats(uapi string) (map[string]PeerStats, []string, error) {
	out := map[string]PeerStats{}
	var order []string
	var cur string
	var st PeerStats
	var sec, nsec int64
	flush := func() {
		if cur == "" {
			return
		}
		if sec > 0 {
			st.LastHandshake = time.Unix(sec, nsec)
		}
		raw, _ := hex.DecodeString(cur)
		out[base64.StdEncoding.EncodeToString(raw)] = st
		order = append(order, cur)
	}
	for _, line := range strings.Split(uapi, "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch k {
		case "public_key":
			flush()
			cur, st, sec, nsec = v, PeerStats{}, 0, 0
		case "last_handshake_time_sec":
			sec, _ = strconv.ParseInt(v, 10, 64)
		case "last_handshake_time_nsec":
			nsec, _ = strconv.ParseInt(v, 10, 64)
		case "rx_bytes":
			st.RxBytes, _ = strconv.ParseInt(v, 10, 64)
		case "tx_bytes":
			st.TxBytes, _ = strconv.ParseInt(v, 10, 64)
		case "endpoint":
			st.Endpoint = v
		}
	}
	flush()
	return out, order, nil
}

func keyHex(b64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(raw) != 32 {
		return "", fmt.Errorf("invalid key")
	}
	return hex.EncodeToString(raw), nil
}
