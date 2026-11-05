package sysctl

import (
	"os"
	"path/filepath"
	"testing"
)

func TestApplySkipsCorrectValues(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "net/ipv4/ip_forward")
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("1\n"), 0o444); err != nil { // read-only but already right
		t.Fatal(err)
	}
	if err := Apply(root, map[string]string{"net.ipv4.ip_forward": "1"}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "net/ipv4/x"), []byte("0"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Apply(root, map[string]string{"net.ipv4.x": "2"}); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(root, "net/ipv4/x")); string(b) != "2" {
		t.Fatalf("got %q", b)
	}
}
