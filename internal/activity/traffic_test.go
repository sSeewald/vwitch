package activity

import (
	"bytes"
	"testing"
	"time"
)

func TestTraffic(t *testing.T) {
	now := time.Unix(1_000_000_000, 0) // a multiple of every step
	tr := NewTraffic()
	tr.Observe(now, map[string]Counter{"phone": {1000, 100}})                                 // baseline only
	tr.Observe(now.Add(5*time.Second), map[string]Counter{"phone": {1500, 150}, "x": {9, 9}}) // +500/+50
	tr.Observe(now.Add(15*time.Second), map[string]Counter{"phone": {200, 20}})               // reset: +200/+20

	h := RangeByName("1h")
	s := tr.Series(h, "phone", now.Add(15*time.Second))
	if len(s) != 360 {
		t.Fatalf("points %d", len(s))
	}
	last, prev := s[len(s)-1], s[len(s)-2]
	if prev.Down != 500 || prev.Up != 50 || last.Down != 200 || last.Up != 20 {
		t.Fatalf("buckets %+v %+v", prev, last)
	}
	tot := tr.Totals(RangeByName("24h"), now.Add(15*time.Second))
	if tot["phone"] != (Counter{700, 70}) || tot[Total] != (Counter{700, 70}) {
		t.Fatalf("totals %+v", tot)
	}
	if _, ok := tot["x"]; ok {
		t.Fatal("first observation must only set the baseline")
	}

	var buf bytes.Buffer
	if err := tr.Save(&buf); err != nil {
		t.Fatal(err)
	}
	tr2 := NewTraffic()
	if err := tr2.Load(&buf); err != nil || tr2.Totals(h, now.Add(15*time.Second))["phone"] != (Counter{700, 70}) {
		t.Fatal("save/load")
	}
	// buckets leave the 1h range after an hour but stay in 24h
	later := now.Add(2 * time.Hour)
	tr2.Observe(later, nil)
	if tr2.Totals(h, later)["phone"] != (Counter{}) || tr2.Totals(RangeByName("24h"), later)["phone"] != (Counter{700, 70}) {
		t.Fatal("prune")
	}
}
