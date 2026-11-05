package config

import (
	"bytes"
	"cmp"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sync"

	"go.yaml.in/yaml/v4"
)

// Parse decodes YAML, applies defaults and validates.
func Parse(data []byte) (*Config, error) {
	c := &Config{}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	c.ApplyDefaults()
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

// Marshal encodes the configuration as YAML.
func (c *Config) Marshal() ([]byte, error) {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(c); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Clone returns a deep copy via YAML round trip.
func (c *Config) Clone() *Config {
	data, err := c.Marshal()
	if err != nil {
		panic(fmt.Sprintf("config clone: %v", err))
	}
	out := &Config{}
	if err := yaml.Unmarshal(data, out); err != nil {
		panic(fmt.Sprintf("config clone: %v", err))
	}
	return out
}

// Store guards a configuration file. All writes are validated and atomic.
type Store struct {
	path string
	mu   sync.Mutex
	cur  *Config
}

// Open loads the configuration from path.
func Open(path string) (*Store, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	c, err := Parse(data)
	if err != nil {
		return nil, err
	}
	return &Store{path: path, cur: c}, nil
}

// Create writes a new configuration; it fails if the file exists.
func Create(path string, c *Config) (*Store, error) {
	if _, err := os.Stat(path); err == nil {
		return nil, fmt.Errorf("%s already exists", path)
	}
	s := &Store{path: path}
	if err := s.write(c); err != nil {
		return nil, err
	}
	s.cur = c
	return s, nil
}

// Reload re-reads the file, keeping the old config if the new one is invalid.
func (s *Store) Reload() error {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return err
	}
	c, err := Parse(data)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cur = c
	return nil
}

// Path returns the file location.
func (s *Store) Path() string { return s.path }

// Get returns a copy of the current configuration.
func (s *Store) Get() *Config {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cur.Clone()
}

// Update applies fn to a copy, validates and persists it atomically.
func (s *Store) Update(fn func(*Config) error) (*Config, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := s.cur.Clone()
	if err := fn(next); err != nil {
		return nil, err
	}
	next.ApplyDefaults()
	if err := next.Validate(); err != nil {
		return nil, err
	}
	if err := s.write(next); err != nil {
		return nil, err
	}
	s.cur = next
	return next.Clone(), nil
}

func (s *Store) write(c *Config) error {
	data, err := c.Marshal()
	if err != nil {
		return err
	}
	return WriteFileAtomic(s.path, data, 0o600)
}

// WriteFileAtomic writes via a temp file and rename in the same directory.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }() // no-op after the rename
	err = f.Chmod(perm)
	if err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr // a failed close can mean lost data: never rename then
	}
	if err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// NextClientAddress returns the lowest free host address in the client network.
func (c *Config) NextClientAddress() (netip.Addr, error) {
	used := map[netip.Addr]bool{c.ServerIP(): true}
	for _, cl := range c.Clients {
		used[cl.Address] = true
	}
	p := c.ClientNet()
	for a := p.Addr().Next(); p.Contains(a); a = a.Next() {
		if !p.Contains(a.Next()) { // broadcast
			break
		}
		if !used[a] {
			return a, nil
		}
	}
	return netip.Addr{}, errors.New("client network is full")
}

// NextEgressIndex returns the lowest unused egress index.
func (c *Config) NextEgressIndex() int {
	used := make([]int, 0, len(c.Egresses))
	for _, e := range c.Egresses {
		used = append(used, e.Index)
	}
	for i := 1; ; i++ {
		if !slices.Contains(used, i) {
			return i
		}
	}
}

// NextPriority returns a priority that sorts after all existing egresses.
func (c *Config) NextPriority() int {
	p := 0
	for _, e := range c.Egresses {
		p = max(p, e.Priority)
	}
	return p + 10
}

// SetOrder assigns priorities 10, 20, ... in the given order. Egresses not
// listed keep their relative order after the listed ones.
func (c *Config) SetOrder(names []string) error {
	seen := map[string]bool{}
	for i, n := range names {
		e, ok := c.Egress(n)
		if !ok {
			return fmt.Errorf("unknown egress %q", n)
		}
		if seen[n] {
			return fmt.Errorf("egress %q listed twice", n)
		}
		seen[n] = true
		e.Priority = (i + 1) * 10
	}
	rest := slices.Clone(c.Egresses)
	slices.SortStableFunc(rest, func(a, b Egress) int { return a.Priority - b.Priority })
	p := (len(names) + 1) * 10
	for _, r := range rest {
		if !seen[r.Name] {
			e, _ := c.Egress(r.Name)
			e.Priority = p
			p += 10
		}
	}
	return nil
}

// SortedEgresses returns egresses ordered by priority, then name.
func (c *Config) SortedEgresses() []Egress {
	out := slices.Clone(c.Egresses)
	slices.SortStableFunc(out, func(a, b Egress) int {
		if a.Priority != b.Priority {
			return a.Priority - b.Priority
		}
		return cmp.Compare(a.Name, b.Name)
	})
	return out
}
