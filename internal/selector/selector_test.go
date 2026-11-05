package selector

import (
	"fmt"
	"testing"

	"github.com/sseewald/vwitch/internal/config"
)

var (
	a = Egress{Name: "a", Enabled: true, Healthy: true, Priority: 10, Weight: 1}
	b = Egress{Name: "b", Enabled: true, Healthy: true, Priority: 20, Weight: 3}
)

func down(e Egress) Egress { e.Healthy = false; return e }

func TestDecide(t *testing.T) {
	base := Global{Strategy: config.StrategyFailover, Offline: config.OfflineBlock, AllowDirect: true}
	tests := []struct {
		name string
		g    func(Global) Global
		es   []Egress
		c    Client
		want Target
	}{
		{"failover picks priority", nil, []Egress{b, a}, Client{}, Target{Kind: KindEgress, Egress: "a"}},
		{"failover skips unhealthy", nil, []Egress{down(a), b}, Client{}, Target{Kind: KindEgress, Egress: "b"}},
		{"disabled ignored", nil, []Egress{{Name: "a", Healthy: true}, b}, Client{}, Target{Kind: KindEgress, Egress: "b"}},
		{"none -> block", nil, []Egress{down(a)}, Client{}, Target{Kind: KindBlock}},
		{"kill switch wins", func(g Global) Global { g.KillSwitch, g.Fast = true, true; return g }, []Egress{a}, Client{}, Target{Kind: KindBlock}},
		{"client block", nil, []Egress{a}, Client{Block: true}, Target{Kind: KindBlock}},
		{"global fast", func(g Global) Global { g.Fast = true; return g }, []Egress{a}, Client{}, Target{Kind: KindDirect}},
		{"client fast", nil, []Egress{a}, Client{Fast: true}, Target{Kind: KindDirect}},
		{"fast ignored without direct", func(g Global) Global { g.AllowDirect = false; return g }, []Egress{a}, Client{Fast: true}, Target{Kind: KindEgress, Egress: "a"}},
		{"ask -> portal", func(g Global) Global { g.Offline = config.OfflineAsk; return g }, nil, Client{}, Target{Kind: KindPortal}},
		{"ask confirmed -> direct", func(g Global) Global { g.Offline = config.OfflineAsk; return g }, nil, Client{DirectConfirmed: true}, Target{Kind: KindDirect}},
		{"confirmation irrelevant when egress up", func(g Global) Global { g.Offline = config.OfflineAsk; return g }, []Egress{a}, Client{DirectConfirmed: true}, Target{Kind: KindEgress, Egress: "a"}},
		{"offline direct", func(g Global) Global { g.Offline = config.OfflineDirect; return g }, nil, Client{}, Target{Kind: KindDirect}},
		{"offline direct not allowed", func(g Global) Global { g.Offline, g.AllowDirect = config.OfflineDirect, false; return g }, nil, Client{}, Target{Kind: KindBlock}},
		{"fixed", func(g Global) Global { g.Strategy, g.Fixed = config.StrategyFixed, "b"; return g }, []Egress{a, b}, Client{}, Target{Kind: KindEgress, Egress: "b"}},
		{"fixed down does not fail over", func(g Global) Global { g.Strategy, g.Fixed = config.StrategyFixed, "b"; return g }, []Egress{a, down(b)}, Client{}, Target{Kind: KindBlock}},
		{"client override", nil, []Egress{a, b}, Client{Strategy: config.StrategyFixed, Fixed: "b"}, Target{Kind: KindEgress, Egress: "b"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := base
			if tt.g != nil {
				g = tt.g(g)
			}
			got := Decide(g, tt.es, tt.c)
			if got.Kind != tt.want.Kind || got.Egress != tt.want.Egress {
				t.Fatalf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestWeightedStickyAndProportional(t *testing.T) {
	g := Global{Strategy: config.StrategyWeighted}
	es := []Egress{a, b}
	counts := map[string]int{}
	first := map[string]string{}
	for i := range 4000 {
		c := Client{Name: fmt.Sprintf("client-%d", i)}
		got := Decide(g, es, c).Egress
		counts[got]++
		first[c.Name] = got
	}
	// weights 1:3 -> ~25% / 75%
	if share := float64(counts["a"]) / 4000; share < 0.20 || share > 0.30 {
		t.Fatalf("share of a = %.2f, want ~0.25", share)
	}
	// sticky: same input, same answer; removing b only moves b's clients
	for name, eg := range first {
		if Decide(g, es, Client{Name: name}).Egress != eg {
			t.Fatal("not sticky")
		}
		if eg == "a" && Decide(g, []Egress{a, down(b)}, Client{Name: name}).Egress != "a" {
			t.Fatal("client of a moved although a stayed up")
		}
	}
}
