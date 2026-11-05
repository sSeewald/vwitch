// Package auth protects the admin UI: bcrypt password hashes and in-memory
// sessions with a sliding expiry.
package auth

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// MinPasswordLength is enforced when setting a password.
const MinPasswordLength = 10

// HashPassword returns a bcrypt hash.
func HashPassword(pw string) (string, error) {
	if len(pw) < MinPasswordLength {
		return "", errors.New("password must have at least 10 characters")
	}
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	return string(h), err
}

// CheckPassword compares a password with a hash in constant time.
func CheckPassword(hash, pw string) bool {
	return hash != "" && bcrypt.CompareHashAndPassword([]byte(hash), []byte(pw)) == nil
}

// RandomToken returns n random bytes, URL-safe base64 encoded.
func RandomToken(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// Sessions is an in-memory session store with opaque random tokens (no JWT:
// one server, so server-side sessions are simpler and revocable). Sessions
// end after Idle without use, after Max at the latest, on logout, on a
// password change and on restart; nothing secret is persisted.
type Sessions struct {
	Idle time.Duration
	Max  time.Duration
	now  func() time.Time

	mu   sync.Mutex
	data map[string]session
}

type session struct{ created, expires time.Time }

// NewSessions creates a store.
func NewSessions(idle, max time.Duration) *Sessions {
	return &Sessions{Idle: idle, Max: max, now: time.Now, data: map[string]session{}}
}

// Create starts a session and returns its token. A new token is issued on
// every login, so a token known before login is never accepted.
func (s *Sessions) Create() string {
	t := RandomToken(32)
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for k, v := range s.data { // drop expired sessions
		if now.After(v.expires) {
			delete(s.data, k)
		}
	}
	s.data[t] = session{created: now, expires: s.expiry(now, now)}
	return t
}

// Valid checks a session and extends its idle timeout.
func (s *Sessions) Valid(token string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.data[token]
	now := s.now()
	if !ok || now.After(v.expires) {
		delete(s.data, token)
		return false
	}
	v.expires = s.expiry(v.created, now)
	s.data[token] = v
	return true
}

func (s *Sessions) expiry(created, now time.Time) time.Time {
	if idle, hard := now.Add(s.Idle), created.Add(s.Max); idle.Before(hard) {
		return idle
	}
	return created.Add(s.Max)
}

// Delete ends a session.
func (s *Sessions) Delete(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, token)
}

// Clear ends all sessions (after a password change).
func (s *Sessions) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	clear(s.data)
}

// Limiter slows down password guessing per remote address.
type Limiter struct {
	mu    sync.Mutex
	fails map[string][]time.Time
}

// NewLimiter creates a limiter.
func NewLimiter() *Limiter { return &Limiter{fails: map[string][]time.Time{}} }

const (
	maxFails   = 5
	failWindow = 10 * time.Minute
)

// Allowed reports whether addr may try again.
func (l *Limiter) Allowed(addr string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	recent := l.fails[addr][:0]
	for _, t := range l.fails[addr] {
		if now.Sub(t) < failWindow {
			recent = append(recent, t)
		}
	}
	l.fails[addr] = recent
	return len(recent) < maxFails
}

// Fail records a failed attempt.
func (l *Limiter) Fail(addr string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.fails[addr] = append(l.fails[addr], now)
}
