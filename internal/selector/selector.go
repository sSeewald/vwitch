// Package selector decides, per client, where its traffic leaves the server.
// It is pure: no I/O, no kernel access. Package routing/firewall apply the result.
package selector

import (
	"cmp"
	"hash/fnv"
	"math"
	"slices"

	"github.com/sseewald/vwitch/internal/config"
)

// Kind is the class of a decision.
type Kind string

const (
	KindEgress Kind = "egress" // via a WireGuard egress
	KindDirect Kind = "direct" // via the server's own uplink
	KindPortal Kind = "portal" // offline, HTTP goes to the status page, DNS allowed
	KindBlock  Kind = "block"  // nothing leaves
)

// Reason explains a decision. Values are stable codes; the UI translates
// them (i18n key "reason.<code>").
type Reason string

const (
	ReasonKillSwitch      Reason = "kill_switch"      // global kill switch
	ReasonClientBlock     Reason = "client_block"     // client's own kill switch
	ReasonDirectAll       Reason = "direct_all"       // global direct mode
	ReasonDirectClient    Reason = "direct_client"    // client's direct mode
	ReasonNoEgress        Reason = "no_egress"        // offline, blocked
	ReasonOfflineDirect   Reason = "offline_direct"   // offline, policy direct
	ReasonDirectConfirmed Reason = "direct_confirmed" // offline, client confirmed direct
	ReasonAsking          Reason = "asking"           // offline, portal asks the client
	// egress decisions use the strategy name: failover, weighted, fixed
)

// Target is the decision for one client.
type Target struct {
	Kind   Kind
	Egress string // set when Kind == KindEgress
	Reason Reason
}

// Egress is the selector's view of an egress.
type Egress struct {
	Name     string
	Enabled  bool
	Healthy  bool
	Priority int
	Weight   int
}

// Client is the selector's view of a client including its runtime switches.
type Client struct {
	Name            string
	Strategy        config.Strategy // empty: use global
	Fixed           string
	Fast            bool // client chose direct mode
	Block           bool // client's own kill switch
	DirectConfirmed bool // client accepted the direct exit while offline
}

// Global is the server wide policy and switches.
type Global struct {
	Strategy    config.Strategy
	Fixed       string
	Offline     config.OfflinePolicy
	AllowDirect bool
	KillSwitch  bool
	Fast        bool
}

// Decide returns the target for one client.
func Decide(g Global, egresses []Egress, c Client) Target {
	switch {
	case g.KillSwitch:
		return Target{Kind: KindBlock, Reason: ReasonKillSwitch}
	case c.Block:
		return Target{Kind: KindBlock, Reason: ReasonClientBlock}
	case g.AllowDirect && g.Fast:
		return Target{Kind: KindDirect, Reason: ReasonDirectAll}
	case g.AllowDirect && c.Fast:
		return Target{Kind: KindDirect, Reason: ReasonDirectClient}
	}

	strategy, fixed := g.Strategy, g.Fixed
	if c.Strategy != "" {
		strategy, fixed = c.Strategy, c.Fixed
	}
	usable := Usable(egresses)

	var pick string
	switch strategy {
	case config.StrategyFixed:
		if slices.ContainsFunc(usable, func(e Egress) bool { return e.Name == fixed }) {
			pick = fixed
		}
	case config.StrategyWeighted:
		pick = weighted(usable, c.Name)
	default:
		if len(usable) > 0 {
			pick = usable[0].Name
		}
	}
	if pick != "" {
		return Target{Kind: KindEgress, Egress: pick, Reason: Reason(strategy)}
	}
	return offline(g, c)
}

// Usable returns enabled, healthy egresses sorted by priority, then name.
func Usable(egresses []Egress) []Egress {
	var out []Egress
	for _, e := range egresses {
		if e.Enabled && e.Healthy {
			out = append(out, e)
		}
	}
	slices.SortStableFunc(out, func(a, b Egress) int {
		return cmp.Or(cmp.Compare(a.Priority, b.Priority), cmp.Compare(a.Name, b.Name))
	})
	return out
}

func offline(g Global, c Client) Target {
	if !g.AllowDirect {
		return Target{Kind: KindBlock, Reason: ReasonNoEgress}
	}
	switch g.Offline {
	case config.OfflineDirect:
		return Target{Kind: KindDirect, Reason: ReasonOfflineDirect}
	case config.OfflineAsk:
		if c.DirectConfirmed {
			return Target{Kind: KindDirect, Reason: ReasonDirectConfirmed}
		}
		return Target{Kind: KindPortal, Reason: ReasonAsking}
	}
	return Target{Kind: KindBlock, Reason: ReasonNoEgress}
}

// weighted picks an egress by weighted rendezvous hashing: each client sticks
// to its egress, and only clients of a removed egress move when the set changes.
func weighted(usable []Egress, client string) string {
	best, bestScore := "", math.Inf(-1)
	for _, e := range usable {
		h := fnv.New64a()
		h.Write([]byte(client))
		h.Write([]byte{0})
		h.Write([]byte(e.Name))
		// uniform in (0,1)
		u := (float64(mix(h.Sum64())>>11) + 0.5) / float64(1<<53)
		score := -float64(max(e.Weight, 1)) / math.Log(u)
		if score > bestScore {
			best, bestScore = e.Name, score
		}
	}
	return best
}

// mix is the splitmix64 finalizer; FNV alone mixes the last bytes poorly.
func mix(x uint64) uint64 {
	x ^= x >> 30
	x *= 0xbf58476d1ce4e5b9
	x ^= x >> 27
	x *= 0x94d049bb133111eb
	x ^= x >> 31
	return x
}
