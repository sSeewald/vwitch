package clients

import (
	"net/netip"
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
	c.Ingresses[0].AWG = config.AWGParams{Jc: 4, Jmin: 40, Jmax: 200, S1: 10, S2: 20, S3: 1, S4: 2,
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

func TestRenderAWG31(t *testing.T) {
	c := config.New()
	k, _ := wgtypes.GeneratePrivateKey()
	c.Server.PrivateKey, c.Server.Endpoint = k.String(), "203.0.113.10"
	c.Ingresses[0].AWG = config.AWGParams{Jc: 4, Jmin: 40, Jmax: 200, S1: 20, S2: 30, S3: 12, S4: 12,
		H1: "1-2", H2: "3-4", H3: "5-6", H4: "7-8", ContentPadding: "8-96", DisableCookies: true}
	cl := config.Client{Name: "old", Address: netip.MustParseAddr("10.8.0.2")}
	get := func(cl config.Client, key string) string {
		out, err := Render(c, cl, "x")
		if err != nil {
			t.Fatal(err)
		}
		f, _ := wgconf.Parse(out)
		return f.Interface().Get(key)
	}
	if get(cl, "ContentPaddingAddition") != "" || get(cl, "DisableCookies") != "" {
		t.Fatal("a client without AWG 3.1 must get the plain config")
	}
	before := Fingerprint(c, cl)
	cl.AWG3 = true
	if get(cl, "ContentPaddingAddition") != "8-96" || get(cl, "HeaderProtectionKey") != "" || Fingerprint(c, cl) == before {
		t.Fatal("AWG 3.1 client")
	}
	cl.AWG3 = false
	c.Ingresses[0].AWG.HeaderProtectionKey, c.Ingresses[0].AWG.RandomTrailers = "a2V5", true
	if get(cl, "HeaderProtectionKey") != "a2V5" || get(cl, "RandomTrailers") != "1" {
		t.Fatal("strict mode must reach every client")
	}
}
