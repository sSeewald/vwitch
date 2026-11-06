// Package health judges egress health from handshake age and active probes,
// with hysteresis so the selection does not flap.
package health

import "time"

// Tracker holds the hysteresis state of one egress. The zero value is
// "unknown"; the first observation is taken as is so startup is fast.
type Tracker struct {
	Rise, Fall int

	known   bool
	healthy bool
	streak  int // consecutive observations disagreeing with the current state
}

// Observe feeds one check result and reports the resulting state and
// whether it changed.
func (t *Tracker) Observe(ok bool) (healthy, changed bool) {
	if !t.known {
		t.known, t.healthy = true, ok
		return ok, true
	}
	if ok == t.healthy {
		t.streak = 0
		return t.healthy, false
	}
	t.streak++
	need := t.Fall
	if ok {
		need = t.Rise
	}
	if t.streak >= max(need, 1) {
		t.healthy, t.streak = ok, 0
		return t.healthy, true
	}
	return t.healthy, false
}

// Healthy returns the current state.
func (t *Tracker) Healthy() bool { return t.known && t.healthy }

// Known reports whether the tracker has seen at least one check.
func (t *Tracker) Known() bool { return t.known }

// Check combines the inputs of one health check.
type Check struct {
	HandshakeAge time.Duration // negative: never
	MaxAge       time.Duration
	ProbesOK     int
	Probes       int
}

// OK reports whether a single check passes: a recent handshake and, if
// probes are configured, at least one successful probe.
func (c Check) OK() bool {
	if c.HandshakeAge < 0 || c.HandshakeAge > c.MaxAge {
		return false
	}
	return c.Probes == 0 || c.ProbesOK > 0
}

// HandshakeAge returns the age of a handshake, or -1 if there was none.
func HandshakeAge(now, last time.Time) time.Duration {
	if last.IsZero() || last.Unix() <= 0 {
		return -1
	}
	return now.Sub(last)
}
