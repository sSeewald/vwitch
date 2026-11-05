// Package web serves the password protected admin UI. Its renderer is also
// used by the client portal so both share layout, design and translations.
package web

import (
	"bytes"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"slices"
	"strings"

	"github.com/sseewald/vwitch/internal/certs"
	"github.com/sseewald/vwitch/internal/config"
	"github.com/sseewald/vwitch/internal/daemon"
	"github.com/sseewald/vwitch/internal/i18n"
	"github.com/sseewald/vwitch/internal/state"
	"github.com/sseewald/vwitch/internal/version"
	assets "github.com/sseewald/vwitch/web"
)

// Page is the data every template receives.
type Page struct {
	Lang   string
	Langs  []string
	Title  string
	Path   string
	Admin  bool
	Narrow bool
	Center bool // centered brand + card, preferences in the footer (login)
	Nav    []NavItem
	Error  string
	Data   any
}

// NavItem is one admin navigation entry.
type NavItem struct{ Path, Label string }

// Renderer holds one parsed template set per page.
type Renderer struct {
	pages map[string]*template.Template
}

var funcs = template.FuncMap{
	"t":           i18n.T,
	"list":        func(v ...string) []string { return v },
	"inc":         func(i int) int { return i + 1 },
	"version":     version.String,
	"repoURL":     func() string { return version.RepoURL },
	"selfSigned":  certs.IsSelfSigned,
	"fingerprint": certs.Fingerprint,
	"hasAction": func(a []config.PortalAction, x string) bool {
		return slices.Contains(a, config.PortalAction(x))
	},
	"join": strings.Join,
	"joinActions": func(a []config.PortalAction) string {
		s := make([]string, len(a))
		for i, x := range a {
			s[i] = string(x)
		}
		return strings.Join(s, ", ")
	},
	"reverse": func(e []state.Event) []state.Event {
		out := slices.Clone(e)
		slices.Reverse(out)
		return out
	},
	"online": func(cs []daemon.ClientStatus) int {
		n := 0
		for _, c := range cs {
			if c.Online {
				n++
			}
		}
		return n
	},
	"age": func(sec float64) string {
		switch {
		case sec < 0:
			return "–"
		case sec < 120:
			return fmt.Sprintf("%.0f s", sec)
		case sec < 7200:
			return fmt.Sprintf("%.0f min", sec/60)
		}
		return fmt.Sprintf("%.0f h", sec/3600)
	},
	"rate": func(bps float64) string {
		units := []string{"B", "kB", "MB", "GB"}
		i := 0
		for bps >= 1000 && i < len(units)-1 {
			bps /= 1000
			i++
		}
		return fmt.Sprintf("%.0f %s", bps, units[i])
	},
	"exitLabel": func(lang, exit, egress string) string {
		if exit == "" {
			return i18n.T(lang, "exit.none")
		}
		if exit == "egress" {
			return i18n.T(lang, "exit.egress", egress)
		}
		return i18n.T(lang, "exit."+exit)
	},
	"resolveOf": func(c *config.Config, name string) string {
		if e, ok := c.Egress(name); ok {
			return string(e.Resolve)
		}
		return ""
	},
	// route is the client's "connection" choice for the select
	"hasPrefix": strings.HasPrefix,
	"route": func(c daemon.ClientStatus) string {
		switch {
		case c.Fast:
			return "direct"
		case c.Strategy == string(config.StrategyFixed):
			return "egress:" + c.Fixed
		case c.Strategy != "":
			return "strategy:" + c.Strategy
		}
		return "auto"
	},
	"eventText": func(lang string, e state.Event) string { return i18n.Msg(lang, "event."+e.Key, e.Args) },
	"reasonText": func(lang, code string) string {
		if code == "" {
			return ""
		}
		return i18n.T(lang, "reason."+code)
	},
}

// NewRenderer parses layout + each page.
func NewRenderer() (*Renderer, error) {
	layout, err := fs.ReadFile(assets.Templates, "templates/layout.html")
	if err != nil {
		return nil, err
	}
	entries, err := fs.ReadDir(assets.Templates, "templates")
	if err != nil {
		return nil, err
	}
	r := &Renderer{pages: map[string]*template.Template{}}
	for _, e := range entries {
		name := strings.TrimSuffix(e.Name(), ".html")
		if name == "layout" {
			continue
		}
		t, err := template.New(name).Funcs(funcs).Parse(string(layout))
		if err != nil {
			return nil, err
		}
		if t, err = t.ParseFS(assets.Templates, "templates/"+e.Name()); err != nil {
			return nil, err
		}
		r.pages[name] = t
	}
	return r, nil
}

// Page renders a full page.
func (r *Renderer) Page(w http.ResponseWriter, name string, p Page) {
	r.exec(w, name, "layout", p)
}

// Fragment renders a named block of a page (for SSE and htmx swaps).
func (r *Renderer) Fragment(name, block string, p Page) (string, error) {
	var b bytes.Buffer
	t, ok := r.pages[name]
	if !ok {
		return "", fmt.Errorf("unknown page %q", name)
	}
	err := t.ExecuteTemplate(&b, block, p)
	return b.String(), err
}

func (r *Renderer) exec(w http.ResponseWriter, name, block string, p Page) {
	if p.Langs == nil {
		p.Langs = i18n.Languages
	}
	out, err := r.Fragment(name, block, p)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(out))
}

// Static serves embedded assets.
func Static() http.Handler {
	sub, _ := fs.Sub(assets.Static, "static")
	return http.StripPrefix("/static/", http.FileServerFS(sub))
}

// LangMiddleware stores ?lang=xx in a cookie and redirects to the clean URL.
func LangMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if l := r.URL.Query().Get("lang"); l != "" && i18n.Supported(l) {
			http.SetCookie(w, &http.Cookie{Name: i18n.Cookie, Value: l, Path: "/", MaxAge: 365 * 24 * 3600,
				SameSite: http.SameSiteLaxMode, HttpOnly: true})
			http.Redirect(w, r, r.URL.Path, http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r)
	})
}
