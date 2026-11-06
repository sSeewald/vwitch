package auth

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPassword(t *testing.T) {
	if _, err := HashPassword("short"); err == nil {
		t.Fatal("short password accepted")
	}
	h, err := HashPassword("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if !CheckPassword(h, "correct horse battery") || CheckPassword(h, "wrong") || CheckPassword("", "") {
		t.Fatal("check failed")
	}
}

func TestSessions(t *testing.T) {
	now := time.Unix(0, 0)
	s := NewSessions(time.Hour, 24*time.Hour)
	s.now = func() time.Time { return now }
	tok := s.Create()
	now = now.Add(50 * time.Minute)
	if !s.Valid(tok) {
		t.Fatal("expired too early")
	}
	now = now.Add(50 * time.Minute) // sliding expiry extended it
	if !s.Valid(tok) {
		t.Fatal("not extended")
	}
	now = now.Add(2 * time.Hour)
	if s.Valid(tok) {
		t.Fatal("not expired")
	}
}

func TestSessionMaxAge(t *testing.T) {
	now := time.Unix(0, 0)
	s := NewSessions(time.Hour, 3*time.Hour)
	s.now = func() time.Time { return now }
	tok := s.Create()
	for range 5 { // keep it busy: idle never expires
		now = now.Add(50 * time.Minute)
		if now.Before(time.Unix(0, 0).Add(3*time.Hour)) && !s.Valid(tok) {
			t.Fatal("session ended before max age")
		}
	}
	if s.Valid(tok) {
		t.Fatal("session outlived max age")
	}
}

func TestLimiter(t *testing.T) {
	l := NewLimiter()
	now := time.Unix(0, 0)
	for range maxFails {
		l.Fail("a", now)
	}
	if l.Allowed("a", now) || !l.Allowed("b", now) {
		t.Fatal("limiter")
	}
	if !l.Allowed("a", now.Add(failWindow+time.Second)) {
		t.Fatal("window")
	}
}

func TestSessionsPersist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sessions.json")
	a := NewSessions(time.Hour, 24*time.Hour)
	if err := a.Persist(path); err != nil {
		t.Fatal(err)
	}
	tok, gone := a.Create(), a.Create()
	a.Delete(gone)
	if b, _ := os.ReadFile(path); strings.Contains(string(b), tok) {
		t.Fatal("token stored in clear")
	}
	b := NewSessions(time.Hour, 24*time.Hour) // after a restart
	if err := b.Persist(path); err != nil {
		t.Fatal(err)
	}
	if !b.Valid(tok) || b.Valid(gone) {
		t.Fatal("sessions not restored")
	}
	b.Clear()
	c := NewSessions(time.Hour, 24*time.Hour)
	_ = c.Persist(path)
	if c.Valid(tok) {
		t.Fatal("cleared session restored")
	}
}
