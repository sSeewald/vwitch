package blocking

import (
	"testing"
	"time"
)

func TestMatcher(t *testing.T) {
	m := NewMatcher(DomainSource{Name: SourceCustom, Domains: []string{"ads.example", "tracker.org"}},
		DomainSource{Name: "list", Domains: []string{"tracker.org", "evil.test"}})
	for name, want := range map[string]string{
		"ads.example.":       SourceCustom,
		"x.ADS.example":      SourceCustom,
		"tracker.org":        SourceCustom, // first source wins
		"a.b.evil.test":      "list",
		"example":            "",
		"notads.example":     "",
		"tracker.org.evil.x": "",
	} {
		s, _, ok := m.Match(name)
		if s != want || ok != (want != "") {
			t.Errorf("Match(%q) = %q %v, want %q", name, s, ok, want)
		}
	}
	var nilM *Matcher
	if _, _, ok := nilM.Match("x.y"); ok || nilM.Len() != 0 {
		t.Fatal("nil matcher")
	}
}

func TestLog(t *testing.T) {
	l := NewLog(3)
	for i := range 5 {
		l.Add(Event{Time: time.Unix(int64(i), 0), Domain: string(rune('a' + i))})
	}
	got := l.Recent(10, nil)
	if len(got) != 3 || got[0].Domain != "e" || got[2].Domain != "c" || l.Total() != 5 {
		t.Fatalf("%v total %d", got, l.Total())
	}
	if f := l.Recent(10, func(e Event) bool { return e.Domain == "d" }); len(f) != 1 {
		t.Fatal("filter")
	}
	if len(NewLog(4).Recent(5, nil)) != 0 {
		t.Fatal("empty log")
	}
}
