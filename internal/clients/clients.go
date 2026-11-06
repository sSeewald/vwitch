// Package clients creates AmneziaWG client peers and renders their configs.
package clients

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/sseewald/vwitch/internal/config"
	"github.com/sseewald/vwitch/internal/wgconf"
)

// New creates a client with the next free address. Call Rekey before
// appending it to the configuration.
func New(c *config.Config, name string, expires *time.Time) (config.Client, error) {
	if err := config.ValidateName(name); err != nil {
		return config.Client{}, err
	}
	if _, exists := c.Client(name); exists {
		return config.Client{}, fmt.Errorf("client %q already exists", name)
	}
	addr, err := c.NextClientAddress()
	if err != nil {
		return config.Client{}, err
	}
	return config.Client{Name: name, Enabled: true, Address: addr, Expires: expires}, nil
}

// Rekey gives cl fresh keys and returns its config file. The private key
// exists only in the returned text: vwitch never stores it, so a config can
// be shown once and a lost one is replaced, not re-exported.
func Rekey(c *config.Config, cl *config.Client) (string, error) {
	priv, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return "", err
	}
	psk, err := wgtypes.GenerateKey()
	if err != nil {
		return "", err
	}
	cl.PublicKey, cl.PresharedKey = priv.PublicKey().String(), psk.String()
	text, err := Render(c, *cl, priv.String())
	if err != nil {
		return "", err
	}
	cl.Issued = Fingerprint(c, *cl)
	return text, nil
}

// Fingerprint identifies everything in a client's config except its private
// key. When it differs from Client.Issued, the client needs a new config
// (e.g. the endpoint, port, MTU or AWG parameters changed).
func Fingerprint(c *config.Config, cl config.Client) string {
	text, err := Render(c, cl, "")
	if err != nil {
		return ""
	}
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:8])
}

// ServerPublicKey derives the server's public key.
func ServerPublicKey(c *config.Config) (string, error) {
	k, err := wgtypes.ParseKey(c.Server.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("server private key: %w", err)
	}
	return k.PublicKey().String(), nil
}

// Render returns the client's AmneziaWG config file. It contains no IPv6
// and uses vwitch itself as DNS server, so v.witch resolves and queries
// follow the client's egress.
func Render(c *config.Config, cl config.Client, privateKey string) (string, error) {
	if c.Server.Endpoint == "" {
		return "", fmt.Errorf("server.endpoint is not set (vwitch set endpoint <host>)")
	}
	pub, err := ServerPublicKey(c)
	if err != nil {
		return "", err
	}
	f := &wgconf.File{}
	i := f.Add("Interface")
	i.Set("PrivateKey", privateKey)
	i.Set("Address", cl.Address.String()+"/32")
	i.Set("DNS", c.ServerIP().String())
	i.Set("MTU", strconv.Itoa(c.Server.MTU))
	a := c.Server.AWG
	for _, kv := range [][2]string{
		{"Jc", strconv.Itoa(a.Jc)}, {"Jmin", strconv.Itoa(a.Jmin)}, {"Jmax", strconv.Itoa(a.Jmax)},
		{"S1", strconv.Itoa(a.S1)}, {"S2", strconv.Itoa(a.S2)}, {"S3", strconv.Itoa(a.S3)}, {"S4", strconv.Itoa(a.S4)},
		{"H1", a.H1}, {"H2", a.H2}, {"H3", a.H3}, {"H4", a.H4},
	} {
		i.Set(kv[0], kv[1])
	}
	for n, v := range cl.I {
		i.Set(fmt.Sprintf("I%d", n+1), v)
	}
	p := f.Add("Peer")
	p.Set("PublicKey", pub)
	p.Set("PresharedKey", cl.PresharedKey)
	p.Set("Endpoint", fmt.Sprintf("%s:%d", hostForEndpoint(c.Server.Endpoint), c.Server.ListenPort))
	p.Set("AllowedIPs", "0.0.0.0/0")
	p.Set("PersistentKeepalive", "25")
	return f.String(), nil
}

func hostForEndpoint(h string) string {
	for _, r := range h {
		if r == ':' { // literal IPv6
			return "[" + h + "]"
		}
	}
	return h
}
