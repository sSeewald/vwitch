package cloudinit

import (
	"strings"
	"testing"

	"go.yaml.in/yaml/v4"
)

const egressConf = `[Interface]
PrivateKey = cHJpdmF0ZQ==
Address = 192.168.1.201/24
[Peer]
PublicKey = cHVibGlj
Endpoint = home.example.org:51820
`

func TestRender(t *testing.T) {
	out, err := Render(Vars{Version: "v1.2.3", Endpoint: "vpn.example.org", AllowDirect: true,
		NetBirdSetupKey: "KEY", LockdownSSH: true,
		Egresses: []Egress{{Name: "home", Config: egressConf, Resolve: "ipv6"}}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(out, "#cloud-config\n") {
		t.Fatal("missing header")
	}
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("invalid YAML: %v\n%s", err, out)
	}
	for _, want := range []string{
		"releases/download/v1.2.3/install.sh | sh -s -- --version 1.2.3",
		"--endpoint vpn.example.org", "--allow-direct", "--admin-interfaces lo,awg0,wt0", "--lockdown-ssh",
		"vwitch egress add home /root/vwitch-egress/home.conf --resolve ipv6",
		"      PrivateKey = cHJpdmF0ZQ==",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
}

func TestRenderRejects(t *testing.T) {
	if _, err := Render(Vars{LockdownSSH: true}); err == nil {
		t.Fatal("lockdown without NetBird accepted")
	}
	if _, err := Render(Vars{Egresses: []Egress{{Name: "x", Config: "nope"}}}); err == nil {
		t.Fatal("broken egress accepted")
	}
	out, _ := Render(Vars{})
	if !strings.Contains(out, "releases/latest/download/install.sh | sh -s -- --password-file") {
		t.Fatal(out)
	}
}
