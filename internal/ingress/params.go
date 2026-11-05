// Package ingress runs the AmneziaWG server interface. Parameter generation
// is pure; the device backend is linux only.
package ingress

import (
	"fmt"
	"math/rand/v2"
	"slices"

	"github.com/sseewald/vwitch/internal/config"
)

// GenerateParams returns random AWG 2.0 parameters within the ranges known
// to work with common clients. S1+56 never equals S2 and the four header
// ranges never overlap.
func GenerateParams(r *rand.Rand) config.AWGParams {
	between := func(lo, hi int) int { return lo + r.IntN(hi-lo+1) }
	p := config.AWGParams{
		Jc:   between(4, 12),
		Jmin: between(40, 700),
		S1:   between(10, 150),
		S3:   between(1, 32),
		S4:   between(1, 32),
	}
	p.Jmax = p.Jmin + between(100, 300)
	for {
		if p.S2 = between(10, 150); p.S1+56 != p.S2 {
			break
		}
	}
	// four sorted, non-overlapping header ranges
	starts := make([]int, 4)
	for i := range starts {
		starts[i] = between(1_000_000, 4_000_000_000)
	}
	slices.Sort(starts)
	h := make([]string, 4)
	for i, s := range starts {
		width := between(100, 500)
		if i < 3 && s+width >= starts[i+1] {
			width = max(0, starts[i+1]-s-1)
		}
		h[i] = fmt.Sprintf("%d-%d", s, s+width)
	}
	p.H1, p.H2, p.H3, p.H4 = h[0], h[1], h[2], h[3]
	return p
}
