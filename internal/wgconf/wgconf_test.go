package wgconf

import "testing"

const sample = `# exported by some router
[Interface]
PrivateKey = cHJpdg==
Address = 192.168.178.201/24, fd00::201/64
DNS = 192.168.178.1

[Peer]
PublicKey = cHVi
PresharedKey = cHNr
AllowedIPs = 0.0.0.0/0
AllowedIPs = ::/0
Endpoint = home.example.org:51820
PersistentKeepalive = 25
`

func TestParse(t *testing.T) {
	f, err := Parse(sample)
	if err != nil {
		t.Fatal(err)
	}
	if got := f.Interface().Get("address"); got != "192.168.178.201/24, fd00::201/64" {
		t.Fatalf("address %q", got)
	}
	if got := List(f.Peer().Get("AllowedIPs")); len(got) != 2 || got[1] != "::/0" {
		t.Fatalf("allowed ips %v", got)
	}
	if f.Peer().Get("endpoint") != "home.example.org:51820" {
		t.Fatal("endpoint")
	}
}

func TestParseErrors(t *testing.T) {
	for _, in := range []string{"", "Key = v", "[Interface]\nPrivateKey = x"} {
		if _, err := Parse(in); err == nil {
			t.Fatalf("accepted %q", in)
		}
	}
}

func TestRender(t *testing.T) {
	f := &File{}
	i := f.Add("Interface")
	i.Set("PrivateKey", "a")
	i.Set("Jc", "4")
	p := f.Add("Peer")
	p.Set("PublicKey", "b")
	want := "[Interface]\nPrivateKey = a\nJc = 4\n\n[Peer]\nPublicKey = b\n"
	if got := f.String(); got != want {
		t.Fatalf("got %q", got)
	}
	if _, err := Parse(f.String()); err != nil {
		t.Fatal(err)
	}
}
