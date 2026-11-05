package ingress

import (
	"encoding/base64"
	"encoding/hex"
	"net/netip"
	"strings"
	"testing"
)

func key(b byte) (b64, hx string) {
	raw := make([]byte, 32)
	raw[0] = b
	return base64.StdEncoding.EncodeToString(raw), hex.EncodeToString(raw)
}

func TestPeersUAPI(t *testing.T) {
	k1, h1 := key(1)
	_, h2 := key(2)
	out, err := peersUAPI([]string{h1, h2}, []Peer{{PublicKey: k1, Addr: netip.MustParseAddr("10.8.0.2")}})
	if err != nil {
		t.Fatal(err)
	}
	want := "public_key=" + h1 + "\nreplace_allowed_ips=true\nallowed_ip=10.8.0.2/32\n" +
		"public_key=" + h2 + "\nremove=true\n"
	if out != want {
		t.Fatalf("got\n%s", out)
	}
}

func TestParseStats(t *testing.T) {
	k1, h1 := key(1)
	get := strings.Join([]string{"private_key=00", "listen_port=51845", "public_key=" + h1,
		"endpoint=1.2.3.4:5", "last_handshake_time_sec=100", "last_handshake_time_nsec=0",
		"rx_bytes=10", "tx_bytes=20", "errno=0", ""}, "\n")
	st, order, err := parseStats(get)
	if err != nil || len(order) != 1 {
		t.Fatal(err, order)
	}
	s := st[k1]
	if s.RxBytes != 10 || s.TxBytes != 20 || s.LastHandshake.Unix() != 100 || s.Endpoint != "1.2.3.4:5" {
		t.Fatalf("%+v", s)
	}
}
