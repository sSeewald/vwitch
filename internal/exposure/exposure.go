// Package exposure finds services on the host that the internet can reach,
// so the admin UI can point out ports the operator should close. Parsing is
// pure; reading /proc lives in exposure_linux.go.
package exposure

import (
	"bufio"
	"cmp"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

// Socket is a listening TCP or bound UDP socket.
type Socket struct {
	Proto   string         `json:"proto"` // "tcp" or "udp"
	Addr    netip.AddrPort `json:"addr"`
	Inode   uint64         `json:"-"`
	Process string         `json:"process,omitempty"`
}

func (s Socket) String() string { return fmt.Sprintf("%s/%d", s.Proto, s.Addr.Port()) }

// socket states in /proc/net/{tcp,udp}
const (
	tcpListen = "0A"
	udpClose  = "07" // unconnected (bound) UDP socket
)

// ParseProcNet parses /proc/net/tcp, tcp6, udp or udp6 and returns the
// listening (TCP) or bound (UDP) sockets.
func ParseProcNet(r io.Reader, proto string) ([]Socket, error) {
	want := tcpListen
	if proto == "udp" {
		want = udpClose
	}
	var out []Socket
	sc := bufio.NewScanner(r)
	sc.Scan() // header
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 10 || f[3] != want {
			continue
		}
		ap, err := parseAddr(f[1])
		if err != nil {
			return nil, err
		}
		inode, _ := strconv.ParseUint(f[9], 10, 64)
		out = append(out, Socket{Proto: proto, Addr: ap, Inode: inode})
	}
	return out, sc.Err()
}

// parseAddr decodes "0100007F:1F90" (IPv4) or the 32 hex digit IPv6 form;
// the kernel prints each 32 bit word in host (little endian) order.
func parseAddr(s string) (netip.AddrPort, error) {
	host, port, ok := strings.Cut(s, ":")
	if !ok {
		return netip.AddrPort{}, fmt.Errorf("bad address %q", s)
	}
	raw, err := hex.DecodeString(host)
	if err != nil || (len(raw) != 4 && len(raw) != 16) {
		return netip.AddrPort{}, fmt.Errorf("bad address %q", s)
	}
	for i := 0; i < len(raw); i += 4 {
		binary.BigEndian.PutUint32(raw[i:], binary.LittleEndian.Uint32(raw[i:]))
	}
	p, err := strconv.ParseUint(port, 16, 16)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("bad port %q", s)
	}
	a, _ := netip.AddrFromSlice(raw)
	return netip.AddrPortFrom(a.Unmap(), uint16(p)), nil
}

// Exposed returns sockets reachable from other hosts (not loopback or
// link-local, not kernel sockets) that expected does not account for, one
// entry per protocol, port and process.
func Exposed(sockets []Socket, expected func(Socket) bool) []Socket {
	var out []Socket
	seen := map[string]bool{}
	for _, s := range sockets {
		a := s.Addr.Addr()
		if s.Inode == 0 || a.IsLoopback() || a.IsLinkLocalUnicast() || expected(s) {
			continue
		}
		key := fmt.Sprintf("%s/%d/%s", s.Proto, s.Addr.Port(), s.Process)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, s)
	}
	slices.SortFunc(out, func(a, b Socket) int {
		return cmp.Or(cmp.Compare(a.Addr.Port(), b.Addr.Port()), cmp.Compare(a.Proto, b.Proto))
	})
	return out
}

// Public reports whether a is an address other hosts on the internet can
// reach: global unicast, not private (RFC 1918, ULA) and not shared address
// space (RFC 6598, used by CGNAT and overlay VPNs).
func Public(a netip.Addr) bool {
	return a.IsGlobalUnicast() && !a.IsPrivate() && !shared.Contains(a)
}

var shared = netip.MustParsePrefix("100.64.0.0/10")
