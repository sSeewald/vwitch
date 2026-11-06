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
var untranslated = regexp.MustCompile(`\b(nav|egress|settings|dash|client|route)\.[a-z_]+`)

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
		Routes:   []daemon.RouteStatus{{Name: "google", Egress: "home", Domains: []string{"google.de", "youtube.com"}, Active: true, Learned: 3}},
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
		for _, draft := range []routeDraft{{}, {For: "google", Egress: "home", Domains: "kept.example"}, {Name: "new", Domains: "typed.example"}} {
			w := httptest.NewRecorder()
			r.Page(w, "routes", Page{Lang: lang, Admin: true, Nav: nav, Path: "/routes", Data: routesPage{pageData: data, Draft: draft}})
			b := w.Body.String()
			if w.Code != 200 || !strings.Contains(b, "youtube.com") || untranslated.MatchString(b) {
				t.Fatalf("routes page %+v: %s", draft, b)
			}
			if draft.Domains != "" && !strings.Contains(b, draft.Domains) {
				t.Fatalf("draft input lost: %+v", draft)
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

func TestExpiryRoundTrip(t *testing.T) {
	exp, err := parseDate("2030-01-31")
	if err != nil {
		t.Fatal(err)
	}
	last := funcs["lastDay"].(func(*time.Time) time.Time)(exp)
	if got := last.Format("2006-01-02"); got != "2030-01-31" {
		t.Fatalf("saving shifts the date: %s", got)
	}
}
