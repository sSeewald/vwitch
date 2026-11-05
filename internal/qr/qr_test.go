package qr

import (
	"strings"
	"testing"
)

func TestRender(t *testing.T) {
	m, err := Matrix("hello")
	if err != nil {
		t.Fatal(err)
	}
	if len(m) < 21+2*quiet || len(m) != len(m[0]) {
		t.Fatalf("size %d", len(m))
	}
	if m[0][0] || !m[quiet][quiet] { // border white, finder pattern corner dark
		t.Fatal("unexpected modules")
	}
	s, _ := SVG("hello")
	if !strings.HasPrefix(s, "<svg") {
		t.Fatal(s)
	}
	if term, _ := Terminal("hello"); !strings.Contains(term, "▀") {
		t.Fatal("terminal")
	}
}
