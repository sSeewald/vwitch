package health

import (
	"testing"
	"time"
)

func TestTrackerHysteresis(t *testing.T) {
	tr := Tracker{Rise: 2, Fall: 3}
	steps := []struct {
		ok      bool
		healthy bool
		changed bool
	}{
		{true, true, true},   // first observation decides
		{false, true, false}, // 1 fail
		{false, true, false}, // 2 fails
		{true, true, false},  // streak reset
		{false, true, false}, // 1
		{false, true, false}, // 2
		{false, false, true}, // 3 -> down
		{true, false, false}, // 1 ok
		{true, true, true},   // 2 -> up
	}
	for i, s := range steps {
		h, c := tr.Observe(s.ok)
		if h != s.healthy || c != s.changed {
			t.Fatalf("step %d: got (%v,%v) want (%v,%v)", i, h, c, s.healthy, s.changed)
		}
	}
}

func TestCheckOK(t *testing.T) {
	max := 200 * time.Second
	cases := []struct {
		c    Check
		want bool
	}{
		{Check{HandshakeAge: -1, MaxAge: max}, false},
		{Check{HandshakeAge: 10 * time.Second, MaxAge: max}, true},
		{Check{HandshakeAge: 300 * time.Second, MaxAge: max}, false},
		{Check{HandshakeAge: 10 * time.Second, MaxAge: max, Probes: 2}, false},
		{Check{HandshakeAge: 10 * time.Second, MaxAge: max, Probes: 2, ProbesOK: 1}, true},
	}
	for i, c := range cases {
		if got := c.c.OK(); got != c.want {
			t.Fatalf("case %d: got %v", i, got)
		}
	}
}
