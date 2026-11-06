// Package nflog receives packets the firewall logs to an nflog group and
// decodes their addresses. Decoding is pure; listening is linux only.
package nflog

import (
	"encoding/binary"
	"net/netip"
)

// Hit is one logged packet.
type Hit struct {
	Prefix string
	Src    netip.Addr
	Dst    netip.Addr
	Proto  uint8
	DPort  uint16 // TCP/UDP only
}

// Decode reads the IP (v4 or v6) header and the destination port.
func Decode(prefix string, pkt []byte) (Hit, bool) {
	h := Hit{Prefix: prefix}
	if len(pkt) < 1 {
		return h, false
	}
	var l4 []byte
	switch pkt[0] >> 4 {
	case 4:
		ihl := int(pkt[0]&0x0f) * 4
		if len(pkt) < 20 || ihl < 20 || len(pkt) < ihl {
			return h, false
		}
		h.Proto = pkt[9]
		h.Src = netip.AddrFrom4([4]byte(pkt[12:16]))
		h.Dst = netip.AddrFrom4([4]byte(pkt[16:20]))
		l4 = pkt[ihl:]
	case 6:
		if len(pkt) < 40 {
			return h, false
		}
		h.Proto = pkt[6] // extension headers are rare here and only cost the port
		h.Src = netip.AddrFrom16([16]byte(pkt[8:24]))
		h.Dst = netip.AddrFrom16([16]byte(pkt[24:40]))
		l4 = pkt[40:]
	default:
		return h, false
	}
	if (h.Proto == 6 || h.Proto == 17) && len(l4) >= 4 {
		h.DPort = binary.BigEndian.Uint16(l4[2:4])
	}
	return h, true
}

// ProtoName names the common protocols.
func ProtoName(p uint8) string {
	switch p {
	case 1:
		return "icmp"
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 58:
		return "icmpv6"
	}
	return ""
}
