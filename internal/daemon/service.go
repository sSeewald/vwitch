package daemon

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/sseewald/vwitch/internal/auth"
	"github.com/sseewald/vwitch/internal/certs"
	"github.com/sseewald/vwitch/internal/clients"
	"github.com/sseewald/vwitch/internal/config"
	"github.com/sseewald/vwitch/internal/egress"
	"github.com/sseewald/vwitch/internal/state"
)

// update persists a config change and triggers a reconcile.
func (d *Daemon) update(fn func(*config.Config) error) error {
	if _, err := d.cfg.Update(fn); err != nil {
		return err
	}
	d.Trigger()
	return nil
}

// Config returns a copy of the current configuration.
func (d *Daemon) Config() *config.Config { return d.cfg.Get() }

// Reload re-reads vwitch.yaml after manual edits.
func (d *Daemon) Reload() error {
	if err := d.cfg.Reload(); err != nil {
		return err
	}
	d.event("reloaded")
	d.Trigger()
	return nil
}

// EgressOptions are optional settings when adding an egress.
type EgressOptions struct {
	Priority *int                  `json:"priority,omitempty"`
	Weight   *int                  `json:"weight,omitempty"`
	Resolve  *config.ResolveFamily `json:"resolve,omitempty"`
	Tags     *[]string             `json:"tags,omitempty"`
	Enabled  *bool                 `json:"enabled,omitempty"`
}

func (o EgressOptions) apply(e *config.Egress) {
	if o.Priority != nil {
		e.Priority = *o.Priority
	}
	if o.Weight != nil {
		e.Weight = *o.Weight
	}
	if o.Resolve != nil {
		e.Resolve = *o.Resolve
	}
	if o.Tags != nil {
		e.Tags = *o.Tags
	}
	if o.Enabled != nil {
		e.Enabled = *o.Enabled
	}
}

// AddEgress imports a wg-quick config as new egress.
func (d *Daemon) AddEgress(name, wgConfig string, o EgressOptions) error {
	if err := config.ValidateName(name); err != nil {
		return err
	}
	e, err := egress.Import(name, wgConfig)
	if err != nil {
		return err
	}
	err = d.update(func(c *config.Config) error {
		if _, ok := c.Egress(name); ok {
			return fmt.Errorf("egress %q already exists", name)
		}
		e.Index, e.Priority = c.NextEgressIndex(), c.NextPriority()
		o.apply(&e)
		c.Egresses = append(c.Egresses, e)
		return nil
	})
	if err == nil {
		d.event("egress_added", name)
	}
	return err
}

// UpdateEgress changes settings of an egress.
func (d *Daemon) UpdateEgress(name string, o EgressOptions) error {
	return d.update(func(c *config.Config) error {
		e, ok := c.Egress(name)
		if !ok {
			return fmt.Errorf("unknown egress %q", name)
		}
		o.apply(e)
		return nil
	})
}

// RemoveEgress deletes an egress.
func (d *Daemon) RemoveEgress(name string) error {
	err := d.update(func(c *config.Config) error {
		for _, r := range c.Routes {
			if r.Egress == name {
				return fmt.Errorf("egress %q is used by route %q: change or remove the route first", name, r.Name)
			}
		}
		n := len(c.Egresses)
		c.Egresses = slices.DeleteFunc(c.Egresses, func(e config.Egress) bool { return e.Name == name })
		if len(c.Egresses) == n {
			return fmt.Errorf("unknown egress %q", name)
		}
		return nil
	})
	if err == nil {
		d.event("egress_removed", name)
	}
	return err
}

// OrderEgresses sets the failover order.
func (d *Daemon) OrderEgresses(names []string) error {
	return d.update(func(c *config.Config) error { return c.SetOrder(names) })
}

// ClientOptions are optional client settings.
type ClientOptions struct {
	Enabled  *bool            `json:"enabled,omitempty"`
	Expires  *time.Time       `json:"expires,omitempty"`
	NoExpiry bool             `json:"no_expiry,omitempty"`
	Strategy *config.Strategy `json:"strategy,omitempty"`
	Fixed    *string          `json:"fixed,omitempty"`
	I        *[]string        `json:"i,omitempty"`
	AWG3     *bool            `json:"awg3,omitempty"`
	Ingress  *string          `json:"ingress,omitempty"`
}

func (o ClientOptions) apply(cl *config.Client) {
	if o.Enabled != nil {
		cl.Enabled = *o.Enabled
	}
	if o.Expires != nil {
		cl.Expires = o.Expires
	}
	if o.NoExpiry {
		cl.Expires = nil
	}
	if o.Strategy != nil {
		cl.Strategy = *o.Strategy
	}
	if o.Fixed != nil {
		cl.Fixed = *o.Fixed
	}
	if o.I != nil {
		cl.I = *o.I
	}
	if o.AWG3 != nil {
		cl.AWG3 = *o.AWG3
	}
	if o.Ingress != nil {
		cl.Ingress = *o.Ingress
	}
}

// AddClient creates a client and returns its config file. This is the only
// time the config (with the private key) exists; see RenewClient.
func (d *Daemon) AddClient(name string, o ClientOptions) (string, error) {
	var out string
	err := d.update(func(c *config.Config) error {
		cl, err := clients.New(c, name, nil)
		if err != nil {
			return err
		}
		if o.Ingress != nil {
			cl.Ingress = *o.Ingress
		}
		in, ok := c.Ingress(cl.Ingress)
		if !ok {
			return fmt.Errorf("unknown ingress %q", cl.Ingress)
		}
		cl.AWG3 = in.AWG.NewClientsAWG3 // the options may still turn it off
		o.apply(&cl)
		if out, err = clients.Rekey(c, &cl); err != nil {
			return err
		}
		c.Clients = append(c.Clients, cl)
		return nil
	})
	if err == nil {
		d.event("client_added", name)
	}
	return out, err
}

// RenewClient replaces a client's keys and returns its new config file. The
// previous config stops working immediately.
func (d *Daemon) RenewClient(name string) (string, error) {
	var out string
	err := d.update(func(c *config.Config) error {
		cl, ok := c.Client(name)
		if !ok {
			return fmt.Errorf("unknown client %q", name)
		}
		var err error
		out, err = clients.Rekey(c, cl)
		return err
	})
	if err == nil {
		d.event("client_renewed", name)
	}
	return out, err
}

// UpdateClient changes a client.
func (d *Daemon) UpdateClient(name string, o ClientOptions) error {
	return d.update(func(c *config.Config) error {
		cl, ok := c.Client(name)
		if !ok {
			return fmt.Errorf("unknown client %q", name)
		}
		o.apply(cl)
		return nil
	})
}

// RemoveClient deletes a client (offboarding) and its runtime switches.
func (d *Daemon) RemoveClient(name string) error {
	err := d.update(func(c *config.Config) error {
		n := len(c.Clients)
		c.Clients = slices.DeleteFunc(c.Clients, func(cl config.Client) bool { return cl.Name == name })
		if len(c.Clients) == n {
			return fmt.Errorf("unknown client %q", name)
		}
		return nil
	})
	if err == nil {
		_ = d.state.Update(func(s *state.Switches) { delete(s.Clients, name) })
		d.event("client_removed", name)
	}
	return err
}

// SetGlobal toggles the global kill switch and/or direct mode.
func (d *Daemon) SetGlobal(killSwitch, fast *bool) error {
	err := d.state.Update(func(s *state.Switches) {
		if killSwitch != nil {
			s.KillSwitch = *killSwitch
		}
		if fast != nil {
			s.Fast = *fast
		}
	})
	if err == nil {
		if killSwitch != nil {
			d.event("killswitch", onOff(*killSwitch))
		}
		if fast != nil {
			d.event("direct_all", onOff(*fast))
		}
		d.Trigger()
	}
	return err
}

// SetClientSwitch toggles a client's own switch. Portal requests are
// checked against web.portal.actions by the caller; admins may set any.
func (d *Daemon) SetClientSwitch(name string, action config.PortalAction, on bool) error {
	if _, ok := d.cfg.Get().Client(name); !ok {
		return fmt.Errorf("unknown client %q", name)
	}
	field := func(cs *state.ClientSwitch) *bool {
		switch action {
		case config.ActionFast:
			return &cs.Fast
		case config.ActionBlock:
			return &cs.Block
		case config.ActionDirect:
			return &cs.DirectConfirmed
		}
		return nil
	}
	cur := d.state.Switches().Clients[name]
	if f := field(&cur); f == nil {
		return fmt.Errorf("unknown action %q", action)
	} else if *f == on {
		return nil // unchanged: no event, no reconcile
	}
	err := d.state.Update(func(s *state.Switches) {
		cs := s.Clients[name]
		*field(&cs) = on
		s.Clients[name] = cs
	})
	if err == nil {
		d.event("client_"+string(action), name, onOff(on))
		d.Trigger()
	}
	return err
}

// PortalActions returns the client actions currently offered.
func (d *Daemon) PortalActions() []config.PortalAction {
	c := d.cfg.Get()
	var out []config.PortalAction
	for _, a := range c.Web.Portal.Actions {
		if a == config.ActionBlock || c.Server.AllowDirect {
			out = append(out, a)
		}
	}
	return out
}

// SetPassword changes the admin password.
func (d *Daemon) SetPassword(pw string) error {
	h, err := auth.HashPassword(pw)
	if err != nil {
		return err
	}
	if err := d.update(func(c *config.Config) error { c.Web.Admin.PasswordHash = h; return nil }); err != nil {
		return err
	}
	d.event("password_changed")
	return nil
}

// InstallTLS validates a PEM certificate and key, stores them next to the
// configuration (tls/cert.pem, tls/key.pem) and uses them for the admin UI.
func (d *Daemon) InstallTLS(certPEM, keyPEM []byte) error {
	if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		return fmt.Errorf("certificate: %w", err)
	}
	dir := filepath.Join(filepath.Dir(d.cfg.Path()), "tls")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := config.WriteFileAtomic(keyFile, keyPEM, 0o600); err != nil {
		return err
	}
	if err := config.WriteFileAtomic(certFile, certPEM, 0o644); err != nil {
		return err
	}
	return d.update(func(c *config.Config) error {
		c.Web.Admin.TLS = config.TLS{CertFile: certFile, KeyFile: keyFile}
		return nil
	})
}

// ResetTLS replaces the admin certificate with a fresh self-signed one.
// The admin UI is HTTPS only, so this is what "remove certificate" means.
// certNames are the names a self-signed admin certificate covers.
func certNames(c *config.Config) []string {
	names := append([]string{}, c.Web.Hostnames...)
	return append(names, c.Server.Endpoint, "localhost", "127.0.0.1", c.ServerIP().String())
}

func (d *Daemon) ResetTLS() error {
	names := certNames(d.Config())
	certPEM, keyPEM, err := certs.SelfSigned(names, d.now())
	if err != nil {
		return err
	}
	if err := d.InstallTLS(certPEM, keyPEM); err != nil {
		return err
	}
	if cert, err := d.Certificate(); err == nil {
		d.log.Info("generated self-signed admin certificate", "names", names, "sha256", certs.Fingerprint(cert))
	}
	return nil
}

// EnsureTLS makes sure the admin UI has a usable certificate: it creates a
// self-signed one when none is configured or the configured one is broken,
// and renews its own self-signed certificate before it expires. Certificates
// installed by the operator are never replaced.
func (d *Daemon) EnsureTLS() error {
	cert, err := d.Certificate()
	switch {
	case err != nil:
		d.log.Warn("admin certificate unusable, generating a self-signed one", "err", err)
	case cert == nil:
	case certs.IsSelfSigned(cert) && d.now().Add(certs.Renew).After(cert.NotAfter):
	case certs.IsSelfSigned(cert) && !certs.Covers(cert, certNames(d.Config())):
		// hostnames or endpoint changed: the browser should see the new name
	default:
		return nil
	}
	return d.ResetTLS()
}

// Certificate returns the configured admin certificate (leaf), or nil.
func (d *Daemon) Certificate() (*x509.Certificate, error) {
	t := d.Config().Web.Admin.TLS
	if !t.Enabled() {
		return nil, nil
	}
	pair, err := tls.LoadX509KeyPair(t.CertFile, t.KeyFile)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(pair.Certificate[0])
}

// SettingKeys lists the keys accepted by Set, for help output.
var SettingKeys = []string{
	"endpoint", "strategy", "fixed", "offline", "resolver", "allow_direct", "lockdown_ssh",
	"hostnames", "language", "portal_actions", "admin_interfaces", "admin_user", "admin_listen", "listen_port",
	"regions.enabled", "regions.mode", "regions.direction", "regions.countries", "activity",
}

// Set changes one setting from its string form. CLI and admin UI share it.
func (d *Daemon) Set(key, value string) error {
	return d.SetMany([][2]string{{key, value}})
}

// SetMany applies several settings as one change: they are validated
// together, so dependent settings (allow_direct and offline) can change at once.
func (d *Daemon) SetMany(kv [][2]string) error {
	err := d.update(func(c *config.Config) error {
		var errs []error
		for _, p := range kv {
			if err := set(c, p[0], strings.TrimSpace(p[1])); err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", p[0], err))
			}
		}
		return errors.Join(errs...)
	})
	if err == nil {
		if terr := d.EnsureTLS(); terr != nil { // new hostnames or endpoint
			d.log.Warn("admin certificate", "err", terr)
		}
	}
	return err
}

func set(c *config.Config, key, value string) error {
	switch key {
	case "endpoint":
		if value == "" {
			return errors.New("must not be empty: clients need the public address of this server")
		}
		c.Server.Endpoint = value
	case "strategy":
		c.Selection.Strategy = config.Strategy(value)
	case "fixed":
		c.Selection.Fixed = value
	case "offline":
		c.Selection.Offline = config.OfflinePolicy(value)
	case "resolver":
		a, err := netip.ParseAddr(value)
		if err != nil {
			return err
		}
		c.DNS.Resolver = a
	case "allow_direct":
		b, err := strconv.ParseBool(value)
		if err != nil {
			return err
		}
		c.Server.AllowDirect = b
		if !b {
			c.Selection.Offline = config.OfflineBlock // ask/direct need the direct exit
		}
	case "lockdown_ssh":
		b, err := strconv.ParseBool(value)
		if err != nil {
			return err
		}
		c.Server.LockdownSSH = b
	case "hostnames":
		c.Web.Hostnames = list(value)
	case "language":
		c.Web.Language = value
	case "portal_actions":
		c.Web.Portal.Actions = nil
		for _, a := range list(value) {
			c.Web.Portal.Actions = append(c.Web.Portal.Actions, config.PortalAction(a))
		}
		if c.Web.Portal.Actions == nil {
			c.Web.Portal.Actions = []config.PortalAction{}
		}
	case "admin_interfaces":
		c.Server.AdminInterfaces = list(value)
	case "admin_user":
		c.Web.Admin.Username = value
	case "admin_listen":
		c.Web.Admin.Listen = value
	case "listen_port":
		p, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return err
		}
		c.Ingresses[0].ListenPort = uint16(p) // the first ingress, as before there were several
	case "regions.enabled":
		b, err := strconv.ParseBool(value)
		if err != nil {
			return err
		}
		c.Security.Regions.Enabled = b
	case "regions.mode":
		c.Security.Regions.Mode = config.RegionMode(value)
	case "regions.direction":
		c.Security.Regions.Direction = config.Direction(value)
	case "regions.countries":
		var cs []string
		for _, x := range list(value) {
			if x = strings.ToUpper(x); !slices.Contains(cs, x) {
				cs = append(cs, x)
			}
		}
		slices.Sort(cs)
		c.Security.Regions.Countries = cs
	case "activity":
		b, err := strconv.ParseBool(value)
		if err != nil {
			return err
		}
		c.Security.NoActivity = !b
	default:
		return fmt.Errorf("unknown setting %q (known: %s)", key, strings.Join(SettingKeys, ", "))
	}
	return nil
}

func list(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// onOff is a translated on/off argument for events.
func onOff(b bool) string {
	if b {
		return "@state.on"
	}
	return "@state.off"
}
