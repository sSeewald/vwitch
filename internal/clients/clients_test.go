package clients

import (
	"strings"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/sseewald/vwitch/internal/config"
	"github.com/sseewald/vwitch/internal/wgconf"
)

func TestNewAndRender(t *testing.T) {
	c := config.New()
	k, _ := wgtypes.GeneratePrivateKey()
	c.Server.PrivateKey = k.String()
	c.Server.Endpoint = "203.0.113.10"
	c.Server.AWG = config.AWGParams{Jc: 4, Jmin: 40, Jmax: 200, S1: 10, S2: 20, S3: 1, S4: 2,
		H1: "1-2", H2: "3-4", H3: "5-6", H4: "7-8"}
	cl, err := New(c, "laptop", nil)
	if err != nil {
		t.Fatal(err)
	}
	if cl.Address.String() != "10.8.0.2" {
		t.Fatalf("address %s", cl.Address)
	}
	out, err := Rekey(c, &cl)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := wgtypes.ParseKey(func() string { f, _ := wgconf.Parse(out); return f.Interface().Get("PrivateKey") }())
	if err != nil || priv.PublicKey().String() != cl.PublicKey {
		t.Fatal("config key does not match the stored public key")
	}
	if cl.Issued == "" || cl.Issued != Fingerprint(c, cl) {
		t.Fatal("fingerprint not recorded")
	}
	c.Server.MTU = 1280 // server change makes the config outdated
	if Fingerprint(c, cl) == cl.Issued {
		t.Fatal("fingerprint ignores MTU")
	}
	c.Server.MTU = config.DefaultMTU
	f, err := wgconf.Parse(out)
	if err != nil {
		t.Fatal(err)
	}
	if f.Peer().Get("Endpoint") != "203.0.113.10:51845" || f.Interface().Get("H3") != "5-6" ||
		f.Interface().Get("DNS") != c.ServerIP().String() || f.Interface().Get("I1") != "" {
		t.Fatal(out)
	}
	if strings.Contains(out, "::") {
		t.Fatal("client config must not contain IPv6")
	}
	c.Clients = append(c.Clients, cl)
	if _, err := New(c, "laptop", nil); err == nil {
		t.Fatal("duplicate accepted")
	}
}
