package blocking

import (
	"net/netip"
	"sync"
	"time"
)

// Event is one blocked lookup or connection.
type Event struct {
	Time     time.Time  `json:"time"`
	Source   string     `json:"source"`
	Client   string     `json:"client,omitempty"` // client name, empty for incoming
	Domain   string     `json:"domain,omitempty"` // blocked DNS name, or the name a blocked address was looked up as
	Addr     netip.Addr `json:"addr,omitzero"`    // remote address of a blocked connection (unset for DNS blocks)
	Port     uint16     `json:"port,omitempty"`
	Proto    string     `json:"proto,omitempty"`
	Country  string     `json:"country,omitempty"`
	Incoming bool       `json:"incoming,omitempty"`
}

// Log keeps the latest events in memory (a ring), newest first on read.
type Log struct {
	mu     sync.Mutex
	events []Event
	next   int
	full   bool
	total  int
}

// NewLog keeps up to size events.
func NewLog(size int) *Log { return &Log{events: make([]Event, size)} }

// Add records an event.
func (l *Log) Add(e Event) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events[l.next] = e
	l.next = (l.next + 1) % len(l.events)
	l.full = l.full || l.next == 0
	l.total++
}

// Recent returns up to n events matching keep (nil: all), newest first.
func (l *Log) Recent(n int, keep func(Event) bool) []Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	size := l.next
	if l.full {
		size = len(l.events)
	}
	var out []Event
	for i := 1; i <= size && len(out) < n; i++ {
		e := l.events[(l.next-i+len(l.events))%len(l.events)]
		if keep == nil || keep(e) {
			out = append(out, e)
		}
	}
	return out
}

// Total is the number of events since start (including dropped ones).
func (l *Log) Total() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.total
}
