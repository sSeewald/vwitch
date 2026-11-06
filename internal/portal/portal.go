// Package portal serves the client status page on the ingress address. It
// identifies the client by its tunnel address, needs no login and doubles
// as captive portal while the offline policy is "ask".
package portal

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/sseewald/vwitch/internal/config"
	"github.com/sseewald/vwitch/internal/daemon"
	"github.com/sseewald/vwitch/internal/i18n"
	"github.com/sseewald/vwitch/internal/web"
)

// Portal is the client facing server.
type Portal struct {
	d   *daemon.Daemon
	r   *web.Renderer
	log *slog.Logger
}

// New creates the portal.
func New(d *daemon.Daemon, r *web.Renderer, log *slog.Logger) *Portal {
	return &Portal{d: d, r: r, log: log}
}

// Action is a button on the status page.
type Action struct {
	Action    config.PortalAction
	On        bool
	Label     string
	Note      string
	Secondary bool
}

// View is the portal page model.
type View struct {
	State   string // ok, fast, direct, portal, block, killswitch
	Tone    string // CSS token: ok, warn, bad
	Exit    string
	Client  daemon.ClientStatus
	Actions []Action
}

// BuildView derives what a client sees. Pure for testing.
func BuildView(st daemon.Status, cs daemon.ClientStatus, allowed []config.PortalAction) View {
	v := View{Client: cs, Exit: cs.Egress}
	add := func(a config.PortalAction, on bool, note string, secondary bool) {
		if !slices.Contains(allowed, a) {
			return
		}
		suffix := ".stop"
		if on {
			suffix = ".start"
		}
		v.Actions = append(v.Actions, Action{Action: a, On: on, Label: "portal.action." + string(a) + suffix,
			Note: note, Secondary: secondary})
	}
	switch {
	case st.Switches.KillSwitch:
		v.State, v.Tone = "killswitch", "bad"
	case cs.Block: // paused by the client or the admin, not by a failure
		v.State, v.Tone = "paused", "bad"
		add(config.ActionBlock, false, "", false)
	case cs.Exit == "direct" && (cs.Fast || st.Switches.Fast):
		v.State, v.Tone = "fast", "accent"
		if cs.Fast {
			add(config.ActionFast, false, "", true)
		}
	case cs.Exit == "direct":
		v.State, v.Tone = "direct", "warn"
		if cs.DirectConfirmed {
			add(config.ActionDirect, false, "", true)
		}
	case cs.Exit == "portal":
		v.State, v.Tone = "portal", "bad"
		add(config.ActionDirect, true, "portal.note.direct", false)
	case cs.Exit == "egress":
		v.State, v.Tone = "ok", "ok"
		add(config.ActionFast, true, "portal.note.fast", false)
		add(config.ActionBlock, true, "", true)
	default:
		v.State, v.Tone = "block", "bad"
	}
	return v
}

// Handler answers every path with the status page (captive portal style).
func (p *Portal) Handler() http.Handler {
	m := http.NewServeMux()
	m.Handle("GET /static/", web.Static())
	m.HandleFunc("POST /action", p.action)
	m.HandleFunc("/", p.page)
	// cross-origin protection: a website a client visits cannot flip that
	// client's switches through its browser; the host check closes the same
	// path via DNS rebinding (a foreign name resolving to the server address)
	return hostGuard(p.d.Config, http.NewCrossOriginProtection().Handler(web.LangMiddleware(web.SecurityHeaders(m))))
}

// hostGuard serves only requests addressed to vwitch's own names or the
// server address. Other GETs are redirected to the first name, so the page
// still works as captive portal for any address a client opens; anything
// else is refused.
func hostGuard(conf func() *config.Config, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := conf()
		if ownHost(c, r.Host) {
			next.ServeHTTP(w, r)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		home := c.Server.Address.Addr().String()
		if len(c.Web.Hostnames) > 0 {
			home = c.Web.Hostnames[0]
		}
		w.Header().Set("Cache-Control", "no-store")
		http.Redirect(w, r, "http://"+home+"/", http.StatusFound)
	})
}

// ownHost reports whether a Host header names vwitch itself.
func ownHost(c *config.Config, hostport string) bool {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if a, err := netip.ParseAddr(host); err == nil {
		return a.Unmap() == c.Server.Address.Addr()
	}
	return slices.ContainsFunc(c.Web.Hostnames, func(n string) bool { return strings.EqualFold(n, host) })
}

func (p *Portal) client(r *http.Request) daemon.ClientStatus {
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	if a, err := netip.ParseAddr(host); err == nil {
		if cs, ok := p.d.ClientByAddr(a.Unmap().String()); ok {
			return cs
		}
	}
	return daemon.ClientStatus{}
}

func (p *Portal) page(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	cs := p.client(r)
	lang := i18n.Pick(r, p.d.Config().Web.Language)
	v := BuildView(p.d.Status(), cs, p.d.PortalActions())
	if cs.Name == "" {
		v.Actions = nil
	}
	if v.State != "ok" {
		w.Header().Set("Refresh", "20")
	}
	p.r.Page(w, "portal", web.Page{Lang: lang, Title: "portal.state." + v.State, Narrow: true, Data: v})
}

func (p *Portal) action(w http.ResponseWriter, r *http.Request) {
	cs := p.client(r)
	a := config.PortalAction(r.FormValue("action"))
	on, _ := strconv.ParseBool(r.FormValue("on"))
	switch {
	case cs.Name == "":
		http.Error(w, "unknown client", http.StatusForbidden)
		return
	case !slices.Contains(p.d.PortalActions(), a):
		http.Error(w, "action not allowed", http.StatusForbidden)
		return
	}
	if err := p.d.SetClientSwitch(cs.Name, a, on); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// give the reconcile loop a moment so the next page shows the new state
	time.Sleep(300 * time.Millisecond)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// Serve listens on the server's tunnel address until ctx ends. It retries
// while the ingress interface is still coming up.
func (p *Portal) Serve(ctx context.Context) error {
	c := p.d.Config()
	addr := netip.AddrPortFrom(c.ServerIP(), c.Web.Portal.Port).String()
	srv := &http.Server{Addr: addr, Handler: p.Handler(), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	for {
		err := srv.ListenAndServe()
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		p.log.Warn("portal listen", "addr", addr, "err", err)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(2 * time.Second):
		}
	}
}
