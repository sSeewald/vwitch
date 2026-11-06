package activity

import (
	"bytes"
	"testing"
	"time"
)

func TestTraffic(t *testing.T) {
	now := time.Unix(1_000_000_000, 0) // a multiple of every step
	tr := NewTraffic()
	tr.Observe(now, map[string]Counter{"phone": {Down: 1000, Up: 100}})                                           // baseline only
	tr.Observe(now.Add(5*time.Second), map[string]Counter{"phone": {Down: 1500, Up: 150}, "x": {Down: 9, Up: 9}}) // +500/+50
	tr.Observe(now.Add(15*time.Second), map[string]Counter{"phone": {Down: 200, Up: 20}})                         // reset: +200/+20

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
	if tot["phone"] != (Counter{Down: 700, Up: 70}) || tot[Total] != (Counter{Down: 700, Up: 70}) {
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
	if err := tr2.Load(&buf); err != nil || tr2.Totals(h, now.Add(15*time.Second))["phone"] != (Counter{Down: 700, Up: 70}) {
		t.Fatal("save/load")
	}
	// buckets leave the 1h range after an hour but stay in 24h
	later := now.Add(2 * time.Hour)
	tr2.Observe(later, nil)
	if tr2.Totals(h, later)["phone"] != (Counter{}) || tr2.Totals(RangeByName("24h"), later)["phone"] != (Counter{Down: 700, Up: 70}) {
		t.Fatal("prune")
	}
}

func TestTrafficBlocked(t *testing.T) {
	now := time.Unix(1_000_000_000, 0)
	tr := NewTraffic()
	tr.Blocked("phone", now)
	tr.Blocked("phone", now.Add(time.Second))
	tr.Blocked(Total, now) // incoming: no client
	h := RangeByName("1h")
	tot := tr.Totals(h, now.Add(time.Minute))
	if tot["phone"].Blocks != 2 || tot[Total].Blocks != 3 {
		t.Fatalf("%+v", tot)
	}
	pts := tr.Series(h, "phone", now.Add(10*time.Second))
	if pts[len(pts)-2].Blocks != 2 {
		t.Fatalf("bucket %+v", pts[len(pts)-2])
	}
}
