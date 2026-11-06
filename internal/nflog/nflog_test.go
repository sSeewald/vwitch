package nflog

import (
	"net/netip"
	"testing"
)

func TestDecode(t *testing.T) {
	v4 := []byte{0x45, 0, 0, 40, 0, 0, 0, 0, 64, 6, 0, 0, 10, 8, 0, 2, 5, 8, 0, 1, 0xc0, 0x00, 0x01, 0xbb}
	h, ok := Decode("vw|region|out", v4)
	if !ok || h.Src != netip.MustParseAddr("10.8.0.2") || h.Dst != netip.MustParseAddr("5.8.0.1") || h.DPort != 443 || ProtoName(h.Proto) != "tcp" {
		t.Fatalf("%+v", h)
	}
	v6 := make([]byte, 44)
	v6[0], v6[6] = 0x60, 17
	v6[8], v6[23] = 0x2a, 1
	v6[42], v6[43] = 0, 53
	if h, ok := Decode("", v6); !ok || h.Src != netip.MustParseAddr("2a00::1") || h.DPort != 53 {
		t.Fatalf("%+v", h)
	}
	if _, ok := Decode("", []byte{0x45, 0}); ok {
		t.Fatal("short packet")
	}
}
