// Package state keeps runtime state that is not desired configuration:
// manual switches (persisted) and the switch log (in memory).
package state

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/sseewald/vwitch/internal/config"
)

// Switches are manual toggles. They survive restarts.
type Switches struct {
	KillSwitch bool                    `json:"kill_switch"`
	Fast       bool                    `json:"fast"`
	Clients    map[string]ClientSwitch `json:"clients,omitempty"`
}

// ClientSwitch are toggles a client set on its status page.
type ClientSwitch struct {
	Fast            bool `json:"fast,omitempty"`
	Block           bool `json:"block,omitempty"`
	DirectConfirmed bool `json:"direct_confirmed,omitempty"`
}

// Event is one entry of the switch log: an i18n key ("event.<key>") with
// arguments. Arguments starting with "@" are i18n keys themselves.
type Event struct {
	Time time.Time `json:"time"`
	Key  string    `json:"key"`
	Args []string  `json:"args,omitempty"`
}

const logSize = 200

// Store persists switches as JSON and keeps the event log.
type Store struct {
	path string

	mu  sync.Mutex
	sw  Switches
	log []Event
}

// Open loads switches from dir (missing file means defaults).
func Open(dir string) (*Store, error) {
	s := &Store{path: filepath.Join(dir, "state.json")}
	data, err := os.ReadFile(s.path)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return nil, err
	default:
		if err := json.Unmarshal(data, &s.sw); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// Switches returns a copy of the switches.
func (s *Store) Switches() Switches {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.sw
	out.Clients = map[string]ClientSwitch{}
	for k, v := range s.sw.Clients {
		out.Clients[k] = v
	}
	return out
}

// Update changes the switches and persists them.
func (s *Store) Update(fn func(*Switches)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sw.Clients == nil {
		s.sw.Clients = map[string]ClientSwitch{}
	}
	fn(&s.sw)
	for k, v := range s.sw.Clients {
		if v == (ClientSwitch{}) {
			delete(s.sw.Clients, k)
		}
	}
	data, err := json.MarshalIndent(s.sw, "", "  ")
	if err != nil {
		return err
	}
	return config.WriteFileAtomic(s.path, data, 0o600)
}

// Log appends an event.
func (s *Store) Log(key string, args ...string) Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := Event{Time: time.Now(), Key: key, Args: args}
	s.log = append(s.log, e)
	if len(s.log) > logSize {
		s.log = slices.Clone(s.log[len(s.log)-logSize:])
	}
	return e
}

// Events returns the log, newest last.
func (s *Store) Events() []Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.log)
}
