package setup

import (
	"testing"

	"github.com/sseewald/vwitch/internal/auth"
)

func TestNewConfig(t *testing.T) {
	c, pw, err := NewConfig(Options{Endpoint: "203.0.113.5", AllowDirect: true})
	if err != nil {
		t.Fatal(err)
	}
	if !auth.CheckPassword(c.Web.Admin.PasswordHash, pw) {
		t.Fatal("password hash mismatch")
	}
	if c.Server.PrivateKey == "" || c.Server.AWG.H1 == "" || c.Selection.Offline != "ask" {
		t.Fatalf("%+v", c.Server)
	}
	if len(Password()) != 23 {
		t.Fatal(Password())
	}
}
