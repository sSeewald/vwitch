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
	if c.Server.PrivateKey == "" || c.Ingresses[0].AWG.H1 == "" || c.Selection.Offline != "ask" {
		t.Fatalf("%+v", c.Server)
	}
	if len(Password()) != 23 {
		t.Fatal(Password())
	}
}

func TestNewConfigPasswordHash(t *testing.T) {
	h, _ := auth.HashPassword("correct horse battery")
	c, pw, err := NewConfig(Options{Endpoint: "203.0.113.1", PasswordHash: h})
	if err != nil || pw != "" || c.Web.Admin.PasswordHash != h || !auth.CheckPassword(c.Web.Admin.PasswordHash, "correct horse battery") {
		t.Fatal(err, pw)
	}
	if _, _, err := NewConfig(Options{Endpoint: "203.0.113.1", PasswordHash: "plain"}); err == nil {
		t.Fatal("a clear-text password must not pass as hash")
	}
	c, pw, err = NewConfig(Options{Endpoint: "203.0.113.1", Password: "my own password"})
	if err != nil || pw != "my own password" || !auth.CheckPassword(c.Web.Admin.PasswordHash, pw) {
		t.Fatal(err)
	}
}
