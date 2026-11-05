package ingress

import (
	"math/rand/v2"
	"testing"

	"github.com/sseewald/vwitch/internal/config"
)

func TestGenerateParamsValid(t *testing.T) {
	for seed := range uint64(500) {
		p := GenerateParams(rand.New(rand.NewPCG(seed, seed)))
		c := config.New()
		c.Server.PrivateKey = "x"
		c.Server.AWG = p
		if err := c.Validate(); err != nil {
			t.Fatalf("seed %d: %v (%+v)", seed, err, p)
		}
	}
}
