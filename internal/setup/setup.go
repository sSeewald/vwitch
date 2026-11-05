// Package setup creates the initial configuration: server keys, random AWG
// parameters and an admin password.
package setup

import (
	"crypto/rand"
	"math/big"
	mrand "math/rand/v2"
	"net"
	"net/netip"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/sseewald/vwitch/internal/auth"
	"github.com/sseewald/vwitch/internal/config"
	"github.com/sseewald/vwitch/internal/ingress"
)

// Options are the choices for a new installation. Zero values use defaults.
type Options struct {
	Endpoint        string
	ListenPort      uint16
	Address         netip.Prefix
	Resolver        netip.Addr
	AllowDirect     bool
	AdminInterfaces []string
	LockdownSSH     bool
	Language        string
	Username        string // empty: config.DefaultAdminUser
	Password        string // empty: generate one
}

// NewConfig returns a ready configuration and the admin password in clear.
func NewConfig(o Options) (*config.Config, string, error) {
	c := config.New()
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return nil, "", err
	}
	c.Server.PrivateKey = key.String()
	seed := [32]byte{}
	if _, err := rand.Read(seed[:]); err != nil {
		return nil, "", err
	}
	c.Server.AWG = ingress.GenerateParams(mrand.New(mrand.NewChaCha8(seed)))
	c.Server.Endpoint = o.Endpoint
	c.Server.AllowDirect = o.AllowDirect
	c.Server.LockdownSSH = o.LockdownSSH
	if o.ListenPort != 0 {
		c.Server.ListenPort = o.ListenPort
	}
	if o.Address.IsValid() {
		c.Server.Address = o.Address
	}
	if o.Resolver.IsValid() {
		c.DNS.Resolver = o.Resolver
	}
	if len(o.AdminInterfaces) > 0 {
		c.Server.AdminInterfaces = o.AdminInterfaces
	}
	if o.Language != "" {
		c.Web.Language = o.Language
	}
	if o.Username != "" {
		c.Web.Admin.Username = o.Username
	}
	pw := o.Password
	if pw == "" {
		pw = Password()
	}
	if c.Web.Admin.PasswordHash, err = auth.HashPassword(pw); err != nil {
		return nil, "", err
	}
	if o.AllowDirect {
		c.Selection.Offline = config.OfflineAsk
	}
	return c, pw, c.Validate()
}

// Password returns a readable random password (no ambiguous characters).
func Password() string {
	const alphabet = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789"
	b := make([]byte, 20)
	for i := range b {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		b[i] = alphabet[n.Int64()]
	}
	return string(b[:5]) + "-" + string(b[5:10]) + "-" + string(b[10:15]) + "-" + string(b[15:])
}

// DetectEndpoint returns the source address of the default route. No packet
// is sent. Behind NAT this is a private address; the caller should warn.
func DetectEndpoint() (netip.Addr, error) {
	c, err := net.DialTimeout("udp4", "192.0.2.1:9", time.Second) // TEST-NET, never contacted
	if err != nil {
		return netip.Addr{}, err
	}
	defer func() { _ = c.Close() }()
	return c.LocalAddr().(*net.UDPAddr).AddrPort().Addr().Unmap(), nil
}
