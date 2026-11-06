package daemon

import (
	"errors"
	"fmt"
	"slices"

	"github.com/sseewald/vwitch/internal/config"
	"github.com/sseewald/vwitch/internal/ingress"
)

// IngressOptions are the changeable settings of an ingress; nil keeps a value.
type IngressOptions struct {
	ListenPort     *uint16 `json:"listen_port,omitempty"`
	Strict         *bool   `json:"strict,omitempty"`
	Isolated       *bool   `json:"isolated,omitempty"`
	DisableCookies *bool   `json:"disable_cookies,omitempty"`
	ContentPadding *bool   `json:"content_padding,omitempty"`
	NewClientsAWG3 *bool   `json:"new_clients_awg3,omitempty"`
	// Admin lets its clients open the admin UI (adds or removes the
	// interface in server.admin_interfaces). New ingresses: on unless isolated.
	Admin *bool `json:"admin,omitempty"`
}

// setAdmin adds or removes iface in the admin interfaces.
func setAdmin(c *config.Config, iface string, on bool) {
	s := &c.Server
	has := slices.Contains(s.AdminInterfaces, iface)
	switch {
	case on && !has:
		s.AdminInterfaces = append(s.AdminInterfaces, iface)
	case !on && has:
		s.AdminInterfaces = slices.DeleteFunc(s.AdminInterfaces, func(i string) bool { return i == iface })
	}
}

func (o IngressOptions) apply(in *config.Ingress) {
	if o.ListenPort != nil {
		in.ListenPort = *o.ListenPort
	}
	if o.Isolated != nil {
		in.Isolated = *o.Isolated
	}
	a := &in.AWG
	if o.DisableCookies != nil {
		a.DisableCookies = *o.DisableCookies
	}
	if o.NewClientsAWG3 != nil {
		a.NewClientsAWG3 = *o.NewClientsAWG3
	}
	if o.ContentPadding != nil { // a switch: keep the current range while on
		switch {
		case !*o.ContentPadding:
			a.ContentPadding = ""
		case a.ContentPadding == "":
			a.ContentPadding = ingress.DefaultContentPadding
		}
	}
	if o.Strict != nil {
		switch {
		case *o.Strict && !a.Strict():
			*a = ingress.Strict(*a, ingress.NewHeaderProtectionKey(), ingress.NewRand())
		case !*o.Strict && a.Strict():
			*a = ingress.Compatible(*a, ingress.NewRand())
		}
	}
}

// nextPort is the port after the highest one in use.
func nextPort(c *config.Config) uint16 {
	p := uint16(config.DefaultListenPort)
	for _, in := range c.Ingresses {
		p = max(p, in.ListenPort+1)
	}
	return p
}

// AddIngress creates an ingress with new camouflage parameters. Its clients
// may open the admin UI unless it is isolated or o.Admin says otherwise.
func (d *Daemon) AddIngress(name string, o IngressOptions) error {
	err := d.update(func(c *config.Config) error {
		if err := config.ValidateName(name); err != nil {
			return err
		}
		if _, ok := c.Ingress(name); ok {
			return fmt.Errorf("ingress %q already exists", name)
		}
		in := config.Ingress{Name: name, Interface: c.NextIngressIface(), ListenPort: nextPort(c),
			AWG: ingress.GenerateParams(ingress.NewRand())}
		o.apply(&in)
		admin := !in.Isolated
		if o.Admin != nil {
			admin = *o.Admin
		}
		setAdmin(c, in.Interface, admin)
		c.Ingresses = append(c.Ingresses, in)
		return nil
	})
	if err == nil {
		d.event("ingress_added", name)
	}
	return err
}

// SetIngress changes an ingress. A new port or strict mode needs new
// configs for its clients; they are flagged as outdated.
func (d *Daemon) SetIngress(name string, o IngressOptions) error {
	err := d.update(func(c *config.Config) error {
		in, ok := c.Ingress(name)
		if !ok {
			return fmt.Errorf("unknown ingress %q", name)
		}
		o.apply(in)
		if o.Admin != nil {
			setAdmin(c, in.Interface, *o.Admin)
		}
		return nil
	})
	if err == nil {
		d.event("ingress_changed", name)
	}
	return err
}

// RemoveIngress deletes an ingress without clients; the last one stays.
func (d *Daemon) RemoveIngress(name string) error {
	err := d.update(func(c *config.Config) error {
		in, ok := c.Ingress(name)
		if !ok {
			return fmt.Errorf("unknown ingress %q", name)
		}
		if len(c.Ingresses) == 1 {
			return errors.New("the last ingress cannot be removed")
		}
		var users []string
		for _, cl := range c.Clients {
			if cl.Ingress == name {
				users = append(users, cl.Name)
			}
		}
		if len(users) > 0 {
			return fmt.Errorf("ingress %q is used by clients %v: move or remove them first", name, users)
		}
		setAdmin(c, in.Interface, false)
		c.Ingresses = slices.DeleteFunc(c.Ingresses, func(x config.Ingress) bool { return x.Name == name })
		return nil
	})
	if err == nil {
		d.event("ingress_removed", name)
	}
	return err
}
