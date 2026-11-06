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

func TestStrictAndCompatible(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	c := config.New()
	c.Server.PrivateKey = "x"
	c.Server.AWG = GenerateParams(r)
	c.Server.AWG.S3 = 3 // an older installation with a small padding
	key := NewHeaderProtectionKey()

	c.Server.AWG = Strict(c.Server.AWG, key, r)
	a := c.Server.AWG
	if err := c.Validate(); err != nil || !a.Strict() || a.H1 != "1" || a.H4 != "4" || a.S3 < config.MinHeaderProtectionPadding {
		t.Fatalf("strict: %v %+v", err, a)
	}
	c.Server.AWG = Compatible(a, r)
	if err := c.Validate(); err != nil || c.Server.AWG.Strict() || c.Server.AWG.H1 == "1" {
		t.Fatalf("compatible: %v %+v", err, c.Server.AWG)
	}
	if c.Server.AWG.S3 != a.S3 {
		t.Fatal("switching back must keep the paddings")
	}
}

func TestNewParamsAllowHeaderProtection(t *testing.T) {
	for seed := range uint64(200) {
		p := GenerateParams(rand.New(rand.NewPCG(seed, 0)))
		if min(p.S1, p.S2, p.S3, p.S4) < config.MinHeaderProtectionPadding || !p.DisableCookies || p.ContentPadding == "" {
			t.Fatalf("%+v", p)
		}
	}
}
