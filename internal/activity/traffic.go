package activity

import (
	"encoding/json"
	"io"
	"sync"
	"time"
)

// Counter is a pair of byte counts as seen from the client: Down was sent
// to it, Up came from it.
type Counter struct {
	Down int64 `json:"d"`
	Up   int64 `json:"u"`
}

func (c Counter) add(o Counter) Counter { return Counter{c.Down + o.Down, c.Up + o.Up} }

// Range is one zoom level of the traffic history.
type Range struct {
	Name string
	Step time.Duration
	Span time.Duration
}

// Ranges are the available zoom levels.
var Ranges = []Range{
	{"1h", 10 * time.Second, time.Hour},
	{"24h", 5 * time.Minute, 24 * time.Hour},
	{"7d", time.Hour, 7 * 24 * time.Hour},
	{"30d", 6 * time.Hour, 30 * 24 * time.Hour},
}

// RangeByName returns the range, or the first one.
func RangeByName(name string) Range {
	for _, r := range Ranges {
		if r.Name == name {
			return r
		}
	}
	return Ranges[0]
}

// Total is the series key for all clients together.
const Total = ""

// Traffic turns cumulative per-client counters into a bucketed history for
// every range. Safe for concurrent use.
type Traffic struct {
	mu     sync.Mutex
	last   map[string]Counter
	series map[string]map[string]map[int64]Counter // range -> client -> bucket start (unix) -> bytes
}

// NewTraffic creates an empty history.
func NewTraffic() *Traffic {
	return &Traffic{last: map[string]Counter{}, series: map[string]map[string]map[int64]Counter{}}
}

// Observe adds the growth of the cumulative counters since the last call.
// A counter that went down was reset (interface recreated): its new value
// is the growth. A client seen for the first time only sets the baseline.
func (t *Traffic) Observe(now time.Time, cumulative map[string]Counter) {
	t.mu.Lock()
	defer t.mu.Unlock()
	var total Counter
	for client, cur := range cumulative {
		prev, known := t.last[client]
		t.last[client] = cur
		if !known {
			continue
		}
		d := Counter{grow(prev.Down, cur.Down), grow(prev.Up, cur.Up)}
		if d == (Counter{}) {
			continue
		}
		t.add(client, now, d)
		total = total.add(d)
	}
	if total != (Counter{}) {
		t.add(Total, now, total)
	}
	t.prune(now)
}

func grow(prev, cur int64) int64 {
	if cur < prev {
		return cur
	}
	return cur - prev
}

// add books d into every range. Caller holds t.mu.
func (t *Traffic) add(client string, now time.Time, d Counter) {
	for _, r := range Ranges {
		byClient := t.series[r.Name]
		if byClient == nil {
			byClient = map[string]map[int64]Counter{}
			t.series[r.Name] = byClient
		}
		b := byClient[client]
		if b == nil {
			b = map[int64]Counter{}
			byClient[client] = b
		}
		k := now.Truncate(r.Step).Unix()
		b[k] = b[k].add(d)
	}
}

// prune drops buckets outside their range. Caller holds t.mu.
func (t *Traffic) prune(now time.Time) {
	for _, r := range Ranges {
		oldest := now.Add(-r.Span).Truncate(r.Step).Unix()
		for client, b := range t.series[r.Name] {
			for k := range b {
				if k < oldest {
					delete(b, k)
				}
			}
			if len(b) == 0 {
				delete(t.series[r.Name], client)
			}
		}
	}
}

// Point is one bucket of a series.
type Point struct {
	T int64 `json:"t"` // bucket start, unix seconds
	Counter
}

// Series returns every bucket of the range up to now (zero when idle),
// oldest first, for one client or Total.
func (t *Traffic) Series(r Range, client string, now time.Time) []Point {
	t.mu.Lock()
	defer t.mu.Unlock()
	b := t.series[r.Name][client]
	end := now.Truncate(r.Step)
	n := int(r.Span / r.Step)
	out := make([]Point, 0, n)
	for i := n - 1; i >= 0; i-- {
		k := end.Add(-time.Duration(i) * r.Step).Unix()
		out = append(out, Point{T: k, Counter: b[k]})
	}
	return out
}

// Totals returns the bytes per client within the range (Total included).
func (t *Traffic) Totals(r Range, now time.Time) map[string]Counter {
	t.mu.Lock()
	defer t.mu.Unlock()
	oldest := now.Add(-r.Span).Unix()
	out := map[string]Counter{}
	for client, b := range t.series[r.Name] {
		for k, c := range b {
			if k >= oldest {
				out[client] = out[client].add(c)
			}
		}
	}
	return out
}

type trafficFile struct {
	Series map[string]map[string]map[int64]Counter `json:"series"`
}

// Save writes the history (not the baselines: counters restart with the
// interface).
func (t *Traffic) Save(w io.Writer) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	return json.NewEncoder(w).Encode(trafficFile{Series: t.series})
}

// Load replaces the history with a saved one.
func (t *Traffic) Load(r io.Reader) error {
	var f trafficFile
	if err := json.NewDecoder(r).Decode(&f); err != nil {
		return err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if f.Series != nil {
		t.series = f.Series
	}
	return nil
}
