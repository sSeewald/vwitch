// Package wgconf parses and renders wg-quick style INI configs, shared by
// egress import (WireGuard) and client export (AmneziaWG).
package wgconf

import (
	"bufio"
	"fmt"
	"strings"
)

// Section is one [Interface] or [Peer] block. Keys keep their first spelling;
// lookups are case-insensitive. Repeated keys are joined with ", ".
type Section struct {
	Name   string
	keys   []string
	values map[string]string
}

// Get returns a value by case-insensitive key.
func (s *Section) Get(key string) string { return s.values[strings.ToLower(key)] }

// Set adds or replaces a key.
func (s *Section) Set(key, value string) {
	if s.values == nil {
		s.values = map[string]string{}
	}
	lk := strings.ToLower(key)
	if _, ok := s.values[lk]; !ok {
		s.keys = append(s.keys, key)
	}
	s.values[lk] = value
}

// File is a parsed config.
type File struct {
	Sections []*Section
}

// Interface returns the first [Interface] section.
func (f *File) Interface() *Section { return f.first("interface") }

// Peer returns the first [Peer] section.
func (f *File) Peer() *Section { return f.first("peer") }

func (f *File) first(name string) *Section {
	for _, s := range f.Sections {
		if strings.EqualFold(s.Name, name) {
			return s
		}
	}
	return nil
}

// Add appends a new section.
func (f *File) Add(name string) *Section {
	s := &Section{Name: name}
	f.Sections = append(f.Sections, s)
	return s
}

// Parse reads a wg-quick config. Comments (# ;) and blank lines are ignored.
func Parse(text string) (*File, error) {
	f := &File{}
	var cur *Section
	sc := bufio.NewScanner(strings.NewReader(text))
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if i := strings.IndexAny(line, "#;"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			cur = f.Add(strings.TrimSpace(line[1 : len(line)-1]))
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok || cur == nil {
			return nil, fmt.Errorf("line %d: expected key = value inside a section", n)
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if old := cur.Get(k); old != "" {
			v = old + ", " + v
		}
		cur.Set(k, v)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if f.Interface() == nil || f.Peer() == nil {
		return nil, fmt.Errorf("config needs an [Interface] and a [Peer] section")
	}
	return f, nil
}

// String renders the config.
func (f *File) String() string {
	var b strings.Builder
	for i, s := range f.Sections {
		if i > 0 {
			b.WriteByte('\n')
		}
		fmt.Fprintf(&b, "[%s]\n", s.Name)
		for _, k := range s.keys {
			fmt.Fprintf(&b, "%s = %s\n", k, s.values[strings.ToLower(k)])
		}
	}
	return b.String()
}

// List splits a comma separated value.
func List(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
