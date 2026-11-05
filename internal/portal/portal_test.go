package portal

import (
	"testing"

	"github.com/sseewald/vwitch/internal/config"
	"github.com/sseewald/vwitch/internal/daemon"
	"github.com/sseewald/vwitch/internal/state"
)

var all = []config.PortalAction{config.ActionFast, config.ActionDirect, config.ActionBlock}

func actions(v View) []string {
	var out []string
	for _, a := range v.Actions {
		out = append(out, a.Label)
	}
	return out
}

func TestBuildView(t *testing.T) {
	tests := []struct {
		name    string
		st      daemon.Status
		cs      daemon.ClientStatus
		allowed []config.PortalAction
		state   string
		labels  int
	}{
		{"ok", daemon.Status{}, daemon.ClientStatus{Name: "a", Exit: "egress", Egress: "home"}, all, "ok", 2},
		{"ok restricted", daemon.Status{}, daemon.ClientStatus{Name: "a", Exit: "egress"}, []config.PortalAction{config.ActionBlock}, "ok", 1},
		{"portal", daemon.Status{}, daemon.ClientStatus{Name: "a", Exit: "portal"}, all, "portal", 1},
		{"direct confirmed", daemon.Status{}, daemon.ClientStatus{Name: "a", Exit: "direct", ClientSwitch: state.ClientSwitch{DirectConfirmed: true}}, all, "direct", 1},
		{"client fast", daemon.Status{}, daemon.ClientStatus{Name: "a", Exit: "direct", ClientSwitch: state.ClientSwitch{Fast: true}}, all, "fast", 1},
		{"global fast", daemon.Status{Switches: state.Switches{Fast: true}}, daemon.ClientStatus{Name: "a", Exit: "direct"}, all, "fast", 0},
		{"kill switch", daemon.Status{Switches: state.Switches{KillSwitch: true}}, daemon.ClientStatus{Name: "a", Exit: "block"}, all, "killswitch", 0},
		{"blocked self", daemon.Status{}, daemon.ClientStatus{Name: "a", Exit: "block", ClientSwitch: state.ClientSwitch{Block: true}}, all, "block", 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := BuildView(tt.st, tt.cs, tt.allowed)
			if v.State != tt.state || len(v.Actions) != tt.labels {
				t.Fatalf("state %s actions %v", v.State, actions(v))
			}
		})
	}
}
