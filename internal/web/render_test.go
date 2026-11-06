package web

import (
	"net/http/httptest"
	"net/netip"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/sseewald/vwitch/internal/activity"
	"github.com/sseewald/vwitch/internal/blocking"
	"github.com/sseewald/vwitch/internal/config"
	"github.com/sseewald/vwitch/internal/daemon"
	"github.com/sseewald/vwitch/internal/state"
)

// TestAllPagesRender executes every template with realistic data in all
// languages, catching template errors and missing translations at build time.
// untranslated finds i18n keys (e.g. "egress.add") that leaked into a page.
var untranslated = regexp.MustCompile(`\b(nav|egress|ingress|settings|dash|client|route|block|act)\.[a-z_]+`)

func TestAllPagesRender(t *testing.T) {
	r, err := NewRenderer()
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.New()
	cfg.Egresses = []config.Egress{{Name: "home", Resolve: config.ResolveIPv6}}
	cfg.Ingresses = append(cfg.Ingresses, config.Ingress{Name: "strict", Interface: "awg1", ListenPort: 51821, Isolated: true,
		AWG: config.AWGParams{HeaderProtectionKey: "k", NewClientsAWG3: true}})
	exp := time.Now().Add(time.Hour)
	st := daemon.Status{
		Egresses: []daemon.EgressStatus{{Name: "home", Enabled: true, Healthy: true, HandshakeAge: 12, LatencyMs: 23, RxRate: 1500}},
		Clients: []daemon.ClientStatus{{Name: "phone", Address: "10.8.0.2", Active: true, Online: true, Exit: "egress", Egress: "home", Expires: &exp,
			Strategy: "fixed", Fixed: "home"}},
		Events: []state.Event{{Time: time.Now(), Key: "switched", Args: []string{"phone", "@exit.block", "home", "@reason.failover"}}},
		Routes: []daemon.RouteStatus{{Name: "google", Egress: "home", Domains: []string{"google.de", "youtube.com"}, Active: true, Learned: 3}},
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
			Egresses: cfg.Egresses, Strategy: "failover", AllowDirect: true, Ingresses: cfg.Ingresses}})
		if b := w.Body.String(); w.Code != 200 || !strings.Contains(b, "phone") || !strings.Contains(b, `name="ingress"`) || !strings.Contains(b, "pill pin") || untranslated.MatchString(b) {
			t.Fatalf("client page: %s", w.Body.String())
		}
		w = httptest.NewRecorder()
		r.Page(w, "ingresses", Page{Lang: lang, Admin: true, Nav: nav, Path: "/ingresses", Data: ingressesPage{pageData: data, Next: 51822,
			Rows: []ingressRow{{Ingress: cfg.Ingresses[0], Status: daemon.IngressStatus{Clients: 1, Online: 1, Admin: true}},
				{Ingress: cfg.Ingresses[1], Traffic: activity.Counter{Down: 2e6, Up: 1e5}}}}})
		if b := w.Body.String(); w.Code != 200 || !strings.Contains(b, "UDP 51821") || !strings.Contains(b, `value="51822"`) ||
			!strings.Contains(b, `/ingresses/strict/delete`) || untranslated.MatchString(b) {
			t.Fatalf("ingresses page: %s", b)
		}
		w = httptest.NewRecorder()
		r.Page(w, "issued", Page{Lang: lang, Admin: true, Data: issuedPage{Name: "phone", Config: "[Interface]", Download: "data:text/plain;base64,"}})
		if b := w.Body.String(); !strings.Contains(b, `download="phone.conf"`) || !strings.Contains(b, `href="data:text/plain`) || untranslated.MatchString(b) {
			t.Fatalf("issued page: %s", b)
		}
		cfg.Security = config.Security{BlockedDomains: []string{"ads.example"},
			Regions: config.Regions{Enabled: true, Mode: config.RegionAllow, Direction: config.DirectionBoth, Countries: []string{"DE"}}}
		sec := securityPage{Config: cfg, Countries: countries(lang), Selected: []Country{country(lang, "DE")},
			Geo: daemon.GeoStatus{Ranges: 3, Updated: time.Now()},
			Log: blockLog{Events: []blocking.Event{
				{Time: time.Now(), Source: blocking.SourceCustom, Client: "phone", Domain: "ads.example"},
				{Time: time.Now(), Source: blocking.SourceRegion, Addr: netip.MustParseAddr("192.0.2.1"), Port: 443, Proto: "tcp", Country: "RU"},
				{Time: time.Now(), Source: blocking.SourceRegion, Addr: netip.MustParseAddr("192.0.2.2"), Country: "CN", Incoming: true}}}}
		w = httptest.NewRecorder()
		r.Page(w, "security", Page{Lang: lang, Admin: true, Nav: nav, Path: "/security", Data: sec})
		if b := w.Body.String(); w.Code != 200 || !strings.Contains(b, "ads.example") || !strings.Contains(b, "🇷🇺") ||
			!strings.Contains(b, `value="DE" checked`) || untranslated.MatchString(b) {
			t.Fatalf("security page: %s", b)
		}
		act := activityPage{Config: cfg, Ranges: activity.Ranges, Range: "24h",
			Totals:  []clientTraffic{{Name: "phone", Bytes: activity.Counter{Down: 5e6, Up: 1e6}, Share: 100}},
			Domains: []activity.DomainStat{{Domain: "ads.example", Queries: 3, Blocked: 3, Clients: []string{"phone"}, Last: time.Now(), Names: []string{"x.ads.example"}}},
			Blocked: map[string]bool{"ads.example": true}, RouteOf: map[string]string{}, Back: "/activity?range=24h"}
		w = httptest.NewRecorder()
		r.Page(w, "activity", Page{Lang: lang, Admin: true, Nav: nav, Path: "/activity", Data: act})
		if b := w.Body.String(); w.Code != 200 || !strings.Contains(b, "x.ads.example") || !strings.Contains(b, "data-chart data-nav") || untranslated.MatchString(b) {
			t.Fatalf("activity page: %s", b)
		}
		cfg.Security = config.Security{}
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

func TestCountries(t *testing.T) {
	cs := countries("de")
	if len(cs) < 240 || len(cs) > 260 {
		t.Fatalf("%d countries", len(cs))
	}
	if c := country("de", "DE"); c.Name != "Deutschland" || c.Flag != "🇩🇪" {
		t.Fatalf("%+v", c)
	}
	if c := country("en", "DE"); c.Name != "Germany" {
		t.Fatalf("%+v", c)
	}
	if flag("eu") != "" || flag("D") != "" {
		t.Fatal("invalid code got a flag")
	}
}
