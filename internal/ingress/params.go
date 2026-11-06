// Package ingress runs the AmneziaWG server interface. Parameter generation
// is pure; the device backend is linux only.
package ingress

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	mrand "math/rand/v2"
	"slices"

	"github.com/sseewald/vwitch/internal/config"
)

// DefaultContentPadding is the random padding range new installations use.
const DefaultContentPadding = "8-96"

// GenerateParams returns random AWG parameters within the ranges known to
// work with common clients. S1+56 never equals S2, the four header ranges
// never overlap, and S1–S4 are large enough for header protection, so it
// can be switched on later without a second round of new configs. The AWG
// 3.1 extras chosen here only affect the server and work with every client.
func GenerateParams(r *mrand.Rand) config.AWGParams {
	between := betweenFn(r)
	p := config.AWGParams{
		Jc:             between(4, 12),
		Jmin:           between(40, 700),
		DisableCookies: true,
		ContentPadding: DefaultContentPadding,
	}
	p.Jmax = p.Jmin + between(100, 300)
	setPaddings(&p, r)
	setHeaders(&p, r)
	return p
}

// Strict switches p to header protection with key: only AWG 3.1 clients
// can connect. Paddings below the minimum are rolled again and the headers
// take the fixed values recommended with header protection.
func Strict(p config.AWGParams, key string, r *mrand.Rand) config.AWGParams {
	if min(p.S1, p.S2, p.S3, p.S4) < config.MinHeaderProtectionPadding {
		setPaddings(&p, r)
	}
	p.H1, p.H2, p.H3, p.H4 = "1", "2", "3", "4"
	p.HeaderProtectionKey, p.RandomTrailers = key, true
	return p
}

// Compatible switches header protection off again, with new random headers.
func Compatible(p config.AWGParams, r *mrand.Rand) config.AWGParams {
	p.HeaderProtectionKey, p.RandomTrailers = "", false
	setHeaders(&p, r)
	return p
}

// NewHeaderProtectionKey returns a random base64 key.
func NewHeaderProtectionKey() string {
	k := make([]byte, 32)
	_, _ = rand.Read(k)
	return base64.StdEncoding.EncodeToString(k)
}

// NewRand returns a generator seeded from crypto/rand.
func NewRand() *mrand.Rand {
	var seed [32]byte
	_, _ = rand.Read(seed[:])
	return mrand.New(mrand.NewChaCha8(seed))
}

func betweenFn(r *mrand.Rand) func(lo, hi int) int {
	return func(lo, hi int) int { return lo + r.IntN(hi-lo+1) }
}

func setPaddings(p *config.AWGParams, r *mrand.Rand) {
	between := betweenFn(r)
	m := config.MinHeaderProtectionPadding
	p.S1, p.S3, p.S4 = between(max(m, 15), 150), between(m, 32), between(m, 32)
	for {
		if p.S2 = between(max(m, 15), 150); p.S1+56 != p.S2 {
			return
		}
	}
}

// setHeaders picks four sorted, non-overlapping header ranges.
func setHeaders(p *config.AWGParams, r *mrand.Rand) {
	between := betweenFn(r)
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
}
