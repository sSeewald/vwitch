package daemon

import (
	"slices"

	"github.com/sseewald/vwitch/internal/exposure"
)

// Security lists what the operator should close or restrict. vwitch only
// manages its own ports; everything else on the host is reported here.
type Security struct {
	Checked     bool              `json:"checked"`
	Error       string            `json:"error,omitempty"`
	Ports       []exposure.Socket `json:"ports"`                  // reachable from outside, not vwitch's
	SSHOpen     bool              `json:"ssh_open"`               // tcp/22 reachable and not locked down
	PublicAdmin []string          `json:"public_admin,omitempty"` // admin interfaces with public addresses
}

// Findings is the number of items that need attention.
func (s Security) Findings() int {
	n := len(s.Ports) + len(s.PublicAdmin)
	if s.Error != "" {
		n++
	}
	return n
}

// Security checks the host for exposed services.
func (d *Daemon) Security() Security {
	c := d.Config()
	sec := Security{Checked: true}
	socks, err := d.sys.Listening()
	if err != nil {
		sec.Error = err.Error()
		return sec
	}
	sshLocked := d.sshLocked(c)
	tunnels := map[uint16]bool{} // egress WireGuard sockets: kernel owned, answer peers only
	for _, e := range c.Egresses {
		if st, err := d.sys.EgressStats(e.Iface()); err == nil && st.ListenPort > 0 {
			tunnels[uint16(st.ListenPort)] = true
		}
	}
	admin := adminPort(c.Web.Admin.Listen)
	sec.Ports = exposure.Exposed(socks, func(s exposure.Socket) bool {
		port := s.Addr.Port()
		switch {
		case c.ClientNet().Contains(s.Addr.Addr()): // portal, DNS: only via awg0
			return true
		case s.Proto == "udp" && (port == c.Server.ListenPort || tunnels[port]): // ingress, egress tunnels
			return true
		case s.Proto == "tcp" && port == admin: // firewall allows admin interfaces only
			return true
		case s.Proto == "tcp" && port == 22 && sshLocked:
			return true
		}
		return false
	})
	sec.SSHOpen = slices.ContainsFunc(sec.Ports, func(s exposure.Socket) bool { return s.Proto == "tcp" && s.Addr.Port() == 22 })
	for _, i := range c.Server.AdminInterfaces {
		if slices.ContainsFunc(d.sys.InterfaceAddrs(i), exposure.Public) {
			sec.PublicAdmin = append(sec.PublicAdmin, i)
		}
	}
	return sec
}
