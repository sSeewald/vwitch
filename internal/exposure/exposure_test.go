package exposure

import (
	"net/netip"
	"strings"
	"testing"
)

const tcp = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1001 1 0
   1: 0100007F:0CEA 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1002 1 0
   2: 0100080A:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1003 1 0
   3: 0100080A:9A8C 0200080A:01BB 01 00000000:00000000 00:00000000 00000000     0        0 1004 1 0
`

const tcp6 = `  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2001 1 0
   1: 00000000000000000000000001000000:1F90 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2002 1 0
`

func TestParseAndFilter(t *testing.T) {
	s4, err := ParseProcNet(strings.NewReader(tcp), "tcp")
	if err != nil {
		t.Fatal(err)
	}
	if len(s4) != 3 || s4[2].Addr != netip.MustParseAddrPort("10.8.0.1:80") {
		t.Fatalf("v4 %v", s4)
	}
	s6, err := ParseProcNet(strings.NewReader(tcp6), "tcp")
	if err != nil {
		t.Fatal(err)
	}
	if len(s6) != 2 || s6[1].Addr != netip.MustParseAddrPort("[::1]:8080") {
		t.Fatalf("v6 %v", s6)
	}
	all := append(s4, s6...)
	for i := range all {
		if all[i].Addr.Port() == 22 {
			all[i].Process = "sshd"
		}
	}
	clientNet := netip.MustParsePrefix("10.8.0.0/24")
	got := Exposed(all, func(s Socket) bool { return clientNet.Contains(s.Addr.Addr()) })
	// loopback, client net and the v4/v6 duplicate of sshd are dropped
	if len(got) != 1 || got[0].Addr.Port() != 22 || got[0].Process != "sshd" {
		t.Fatalf("exposed %v", got)
	}
}

func TestPublic(t *testing.T) {
	for a, want := range map[string]bool{
		"203.0.113.7": true, "2001:db8::1": true, "10.0.0.1": false, "192.168.1.2": false,
		"100.92.4.1": false, "127.0.0.1": false, "fd00::1": false, "fe80::1": false,
	} {
		if got := Public(netip.MustParseAddr(a)); got != want {
			t.Errorf("%s: got %v", a, got)
		}
	}
}
