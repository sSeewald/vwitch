package portal

import (
	"net/http"
	"net/http/httptest"
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
		{"blocked self", daemon.Status{}, daemon.ClientStatus{Name: "a", Exit: "block", ClientSwitch: state.ClientSwitch{Block: true}}, all, "paused", 1},
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

func TestHostGuard(t *testing.T) {
	c := config.New()
	conf := func() *config.Config { return c }
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) })
	h := hostGuard(conf, ok)
	for _, tt := range []struct {
		method, host string
		code         int
	}{
		{"GET", "v.witch", http.StatusTeapot},
		{"POST", "V.Witch.", http.StatusTeapot},
		{"POST", "vwitch.internal:80", http.StatusTeapot},
		{"POST", "10.8.0.1", http.StatusTeapot},
		{"POST", "10.8.0.1:8080", http.StatusTeapot},
		// DNS rebinding: a foreign name pointing at the server address
		{"POST", "attacker.example", http.StatusForbidden},
		{"POST", "10.8.0.2", http.StatusForbidden},
		// captive portal: any page a client opens leads to vwitch
		{"GET", "example.org", http.StatusFound},
	} {
		r := httptest.NewRequest(tt.method, "http://"+tt.host+"/action", nil)
		r.Host = tt.host
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tt.code {
			t.Errorf("%s %s: got %d, want %d", tt.method, tt.host, w.Code, tt.code)
		}
		if w.Code == http.StatusFound && w.Header().Get("Location") != "http://v.witch/" {
			t.Errorf("redirect to %q", w.Header().Get("Location"))
		}
	}
}
