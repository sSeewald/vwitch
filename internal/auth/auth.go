// Package auth protects the admin UI: bcrypt password hashes and server-side
// sessions with a sliding expiry.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
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

// ValidHash reports whether h is a bcrypt hash.
func ValidHash(h string) bool {
	_, err := bcrypt.Cost([]byte(h))
	return err == nil
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

// Sessions is a session store with opaque random tokens (no JWT: one
// server, so server-side sessions are simpler and revocable). Sessions end
// after Idle without use, after Max at the latest, on logout and on a
// password change. With Persist they survive restarts; only SHA-256 hashes
// of the tokens are written, so the file never contains a usable token.
type Sessions struct {
	Idle time.Duration
	Max  time.Duration
	now  func() time.Time

	mu    sync.Mutex
	data  map[string]session // by token hash
	path  string
	saved time.Time
}

type session struct {
	Created time.Time `json:"created"`
	Expires time.Time `json:"expires"`
}

// saveEvery limits writes caused by sliding expiry.
const saveEvery = time.Minute

// NewSessions creates an in-memory store.
func NewSessions(idle, max time.Duration) *Sessions {
	return &Sessions{Idle: idle, Max: max, now: time.Now, data: map[string]session{}}
}

// Persist loads sessions from path and keeps the file up to date.
func (s *Sessions) Persist(path string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.path = path
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return json.Unmarshal(b, &s.data)
}

// save writes the store. Caller holds s.mu.
func (s *Sessions) save(now time.Time) {
	if s.path == "" {
		return
	}
	s.saved = now
	b, err := json.Marshal(s.data)
	if err != nil {
		return
	}
	tmp := s.path + ".tmp"
	if os.WriteFile(tmp, b, 0o600) == nil {
		_ = os.Rename(tmp, s.path)
	}
}

func hashToken(t string) string {
	h := sha256.Sum256([]byte(t))
	return hex.EncodeToString(h[:])
}

// Create starts a session and returns its token. A new token is issued on
// every login, so a token known before login is never accepted.
func (s *Sessions) Create() string {
	t := RandomToken(32)
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for k, v := range s.data { // drop expired sessions
		if now.After(v.Expires) {
			delete(s.data, k)
		}
	}
	s.data[hashToken(t)] = session{Created: now, Expires: s.expiry(now, now)}
	s.save(now)
	return t
}

// Valid checks a session and extends its idle timeout.
func (s *Sessions) Valid(token string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := hashToken(token)
	v, ok := s.data[k]
	now := s.now()
	if !ok || now.After(v.Expires) {
		if ok {
			delete(s.data, k)
			s.save(now)
		}
		return false
	}
	v.Expires = s.expiry(v.Created, now)
	s.data[k] = v
	if now.Sub(s.saved) >= saveEvery {
		s.save(now)
	}
	return true
}

// Lifetime is how long a fresh session cookie may live in the browser.
func (s *Sessions) Lifetime() time.Duration { return s.Max }

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
	delete(s.data, hashToken(token))
	s.save(s.now())
}

// Clear ends all sessions (after a password change).
func (s *Sessions) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	clear(s.data)
	s.save(s.now())
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
