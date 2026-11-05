package web

import (
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/sseewald/vwitch/internal/config"
	"github.com/sseewald/vwitch/internal/daemon"
	"github.com/sseewald/vwitch/internal/state"
)

// TestAllPagesRender executes every template with realistic data in all
// languages, catching template errors and missing translations at build time.
// untranslated finds i18n keys (e.g. "egress.add") that leaked into a page.
var untranslated = regexp.MustCompile(`\b(nav|egress|settings|dash|client)\.[a-z_]+`)

func TestAllPagesRender(t *testing.T) {
	r, err := NewRenderer()
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.New()
	cfg.Egresses = []config.Egress{{Name: "home", Resolve: config.ResolveIPv6}}
	exp := time.Now().Add(time.Hour)
	st := daemon.Status{
		Egresses: []daemon.EgressStatus{{Name: "home", Enabled: true, Healthy: true, HandshakeAge: 12, LatencyMs: 23, RxRate: 1500}},
		Clients:  []daemon.ClientStatus{{Name: "phone", Address: "10.8.0.2", Active: true, Online: true, Exit: "egress", Egress: "home", Expires: &exp}},
		Events:   []state.Event{{Time: time.Now(), Key: "switched", Args: []string{"phone", "@exit.block", "home", "@reason.failover"}}},
	}
	data := pageData{Status: st, Config: cfg, AllowDirect: true}
	for _, lang := range []string{"en", "de"} {
		for _, page := range []string{"dashboard", "egresses", "clients", "settings"} {
			w := httptest.NewRecorder()
			r.Page(w, page, Page{Lang: lang, Admin: true, Nav: nav, Path: "/", Data: data})
			body := w.Body.String()
			if w.Code != 200 || !strings.Contains(body, "</html>") {
				t.Fatalf("%s/%s: %d %s", lang, page, w.Code, body)
			}
			if untranslated.MatchString(body) {
				t.Fatalf("%s/%s: untranslated key in output", lang, page)
			}
		}
		w := httptest.NewRecorder()
		r.Page(w, "client", Page{Lang: lang, Admin: true, Data: clientPage{Client: st.Clients[0],
			Egresses: cfg.Egresses, Strategy: "failover", AllowDirect: true}})
		if w.Code != 200 || !strings.Contains(w.Body.String(), "phone") || untranslated.MatchString(w.Body.String()) {
			t.Fatalf("client page: %s", w.Body.String())
		}
		w = httptest.NewRecorder()
		r.Page(w, "issued", Page{Lang: lang, Admin: true, Data: issuedPage{Name: "phone", Config: "[Interface]", Download: "data:text/plain;base64,"}})
		if b := w.Body.String(); !strings.Contains(b, `download="phone.conf"`) || !strings.Contains(b, `href="data:text/plain`) || untranslated.MatchString(b) {
			t.Fatalf("issued page: %s", b)
		}
		w = httptest.NewRecorder()
		r.Page(w, "login", Page{Lang: lang, Narrow: true, Data: loginData{NoPassword: true}})
		if b := w.Body.String(); !strings.Contains(b, `autocomplete="username"`) || !strings.Contains(b, "current-password") {
			t.Fatal("login page")
		}
	}
}
