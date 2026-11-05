package web

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sseewald/vwitch/internal/auth"
	"github.com/sseewald/vwitch/internal/config"
	"github.com/sseewald/vwitch/internal/daemon"
	"github.com/sseewald/vwitch/internal/i18n"
	"github.com/sseewald/vwitch/internal/qr"
)

const sessionCookie = "vwitch_session"

// Admin is the admin UI server.
type Admin struct {
	d        *daemon.Daemon
	r        *Renderer
	log      *slog.Logger
	sessions *auth.Sessions
	limiter  *auth.Limiter

	mu       sync.Mutex
	lastHash string // sessions end when the password hash changes
}

// NewAdmin creates the admin UI.
func NewAdmin(d *daemon.Daemon, r *Renderer, log *slog.Logger) *Admin {
	return &Admin{d: d, r: r, log: log, sessions: auth.NewSessions(2*time.Hour, 24*time.Hour), limiter: auth.NewLimiter(),
		lastHash: d.Config().Web.Admin.PasswordHash}
}

var nav = []NavItem{
	{"/", "nav.dashboard"}, {"/egresses", "nav.egresses"}, {"/clients", "nav.clients"}, {"/settings", "nav.settings"},
}

// Handler returns the routes, protected against cross-origin requests.
func (a *Admin) Handler() http.Handler {
	m := http.NewServeMux()
	m.Handle("GET /static/", Static())
	m.HandleFunc("GET /login", a.loginPage)
	m.HandleFunc("POST /login", a.login)
	m.HandleFunc("POST /logout", a.logout)

	p := func(pattern string, h http.HandlerFunc) { m.Handle(pattern, a.requireLogin(h)) }
	p("GET /{$}", a.page("dashboard", "nav.dashboard"))
	p("GET /events", a.events)
	p("GET /security", a.security)
	p("POST /switches", a.switches)
	p("GET /egresses", a.page("egresses", "nav.egresses"))
	p("POST /egresses", a.addEgress)
	p("POST /egresses/{name}", a.updateEgress)
	p("POST /egresses/{name}/move", a.moveEgress)
	p("POST /egresses/{name}/delete", a.form("/egresses", "egresses", func(r *http.Request) error {
		return a.d.RemoveEgress(r.PathValue("name"))
	}))
	p("GET /clients", a.page("clients", "nav.clients"))
	p("POST /clients", a.addClient)
	p("GET /clients/{name}", a.client)
	p("POST /clients/{name}", a.updateClient)
	p("POST /clients/{name}/switch", a.clientSwitch)
	p("POST /clients/{name}/delete", a.form("/clients", "clients", func(r *http.Request) error {
		return a.d.RemoveClient(r.PathValue("name"))
	}))
	p("POST /clients/{name}/renew", a.renewClient)
	p("GET /settings", a.page("settings", "nav.settings"))
	p("POST /settings", a.form("/settings", "settings", a.saveSettings))
	p("POST /settings/account", a.form("/settings", "settings", func(r *http.Request) error {
		// every change of the sign-in needs the current password
		host, now := remoteHost(r), time.Now()
		if !a.limiter.Allowed(host, now) {
			return errors.New(i18n.T(a.lang(r), "login.locked"))
		}
		if !auth.CheckPassword(a.d.Config().Web.Admin.PasswordHash, r.FormValue("current_password")) {
			a.limiter.Fail(host, now)
			a.log.Warn("admin account change with wrong password", "remote", host)
			return errors.New(i18n.T(a.lang(r), "settings.current_password.wrong"))
		}
		if u := strings.TrimSpace(r.FormValue("username")); u != a.d.Config().Web.Admin.Username {
			if err := a.d.Set("admin_user", u); err != nil {
				return err
			}
		}
		if pw := r.FormValue("password"); pw != "" {
			return a.d.SetPassword(pw)
		}
		return nil
	}))
	p("POST /settings/tls", a.form("/settings", "settings", a.uploadTLS))
	p("POST /settings/tls/delete", a.form("/settings", "settings", func(*http.Request) error {
		return a.d.ResetTLS()
	}))
	return http.NewCrossOriginProtection().Handler(LangMiddleware(SecurityHeaders(m)))
}

// Serve runs the admin server over HTTPS until ctx ends. It never serves
// plain HTTP: without a configured certificate a self-signed one is created
// and renewed before it expires. The certificate is read per handshake, so
// an upload or 'vwitch tls set' applies without a restart.
func (a *Admin) Serve(ctx context.Context) error {
	if err := a.d.EnsureTLS(); err != nil {
		return fmt.Errorf("admin certificate: %w", err)
	}
	srv := &http.Server{Addr: a.d.Config().Web.Admin.Listen, Handler: a.Handler(), ReadHeaderTimeout: 10 * time.Second,
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: a.certificate}}
	go func() {
		renew := time.NewTicker(24 * time.Hour)
		defer renew.Stop()
		for {
			select {
			case <-ctx.Done():
				sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_ = srv.Shutdown(sctx)
				return
			case <-renew.C:
				if err := a.d.EnsureTLS(); err != nil {
					a.log.Error("renew admin certificate", "err", err)
				}
			}
		}
	}()
	if err := srv.ListenAndServeTLS("", ""); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func (a *Admin) certificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	t := a.d.Config().Web.Admin.TLS
	c, err := tls.LoadX509KeyPair(t.CertFile, t.KeyFile)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// SecurityHeaders sets restrictive browser headers (admin UI and portal).
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "same-origin")
		h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'")
		next.ServeHTTP(w, r)
	})
}

// --- auth ---

func (a *Admin) loggedIn(r *http.Request) bool {
	hash := a.d.Config().Web.Admin.PasswordHash
	a.mu.Lock()
	if hash != a.lastHash {
		a.sessions.Clear()
		a.lastHash = hash
	}
	a.mu.Unlock()
	c, err := r.Cookie(sessionCookie)
	return err == nil && a.sessions.Valid(c.Value)
}

func (a *Admin) requireLogin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !a.loggedIn(r) {
			if r.Header.Get("HX-Request") != "" {
				w.Header().Set("HX-Redirect", "/login")
				return
			}
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (a *Admin) loginPage(w http.ResponseWriter, r *http.Request) {
	a.renderLogin(w, r, "")
}

func (a *Admin) renderLogin(w http.ResponseWriter, r *http.Request, errKey string) {
	lang := a.lang(r)
	adm := a.d.Config().Web.Admin
	p := Page{Lang: lang, Title: "login.title", Narrow: true, Center: true, Data: loginData{NoPassword: adm.PasswordHash == "", Username: r.FormValue("username")}}
	if errKey != "" {
		p.Error = i18n.T(lang, errKey)
	}
	a.r.Page(w, "login", p)
}

type loginData struct {
	NoPassword bool
	Username   string // echoed after a failed attempt
}

func (a *Admin) login(w http.ResponseWriter, r *http.Request) {
	host := remoteHost(r)
	now := time.Now()
	if !a.limiter.Allowed(host, now) {
		a.renderLogin(w, r, "login.locked")
		return
	}
	adm := a.d.Config().Web.Admin
	userOK := subtle.ConstantTimeCompare([]byte(strings.TrimSpace(r.FormValue("username"))), []byte(adm.Username)) == 1
	// always check the password so timing does not reveal the user name
	if !auth.CheckPassword(adm.PasswordHash, r.FormValue("password")) || !userOK {
		a.limiter.Fail(host, now)
		a.log.Warn("admin login failed", "remote", host)
		a.renderLogin(w, r, "login.failed")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: a.sessions.Create(), Path: "/", HttpOnly: true,
		Secure: true, SameSite: http.SameSiteStrictMode})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (a *Admin) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		a.sessions.Delete(c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// --- pages ---

type pageData struct {
	Status      daemon.Status
	Config      *config.Config
	AllowDirect bool
	Cert        *x509.Certificate // admin TLS certificate, nil for HTTP
}

func (a *Admin) data() pageData {
	c := a.d.Config()
	cert, _ := a.d.Certificate()
	return pageData{Status: a.d.Status(), Config: c, AllowDirect: c.Server.AllowDirect, Cert: cert}
}

func (a *Admin) lang(r *http.Request) string { return i18n.Pick(r, a.d.Config().Web.Language) }

func (a *Admin) basePage(r *http.Request, title string) Page {
	return Page{Lang: a.lang(r), Title: title, Path: r.URL.Path, Admin: true, Nav: nav}
}

func (a *Admin) page(name, title string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p := a.basePage(r, title)
		p.Data = a.data()
		a.r.Page(w, name, p)
	}
}

// form runs fn and redirects to back, or re-renders page with the error.
func (a *Admin) form(back, page string, fn func(*http.Request) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := fn(r); err != nil {
			p := a.basePage(r, "nav."+page)
			p.Path = back
			p.Error = err.Error()
			p.Data = a.data()
			a.r.Page(w, page, p)
			return
		}
		http.Redirect(w, r, back, http.StatusSeeOther)
	}
}

// events streams rendered fragments of the dashboard via SSE.
func (a *Admin) events(w http.ResponseWriter, r *http.Request) {
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	ch, cancel := a.d.Subscribe()
	defer cancel()
	lang := a.lang(r)
	send := func() error {
		p := Page{Lang: lang, Admin: true, Data: a.data()}
		for _, ev := range [][2]string{{"overview", "overview"}, {"egresses", "egress-cards"}, {"log", "event-log"}} {
			html, err := a.r.Fragment("dashboard", ev[1], p)
			if err != nil {
				return err
			}
			fmt.Fprintf(w, "event: %s\n", ev[0])
			for _, line := range strings.Split(html, "\n") {
				fmt.Fprintf(w, "data: %s\n", line)
			}
			fmt.Fprint(w, "\n")
		}
		fl.Flush()
		return nil
	}
	keepalive := time.NewTicker(30 * time.Second)
	defer keepalive.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-ch:
			if send() != nil {
				return
			}
		case <-keepalive.C:
			fmt.Fprint(w, ": keepalive\n\n")
			fl.Flush()
		}
	}
}

func (a *Admin) switches(w http.ResponseWriter, r *http.Request) {
	var kill, fast *bool
	if v := r.FormValue("kill_switch"); v != "" {
		b := v == "true"
		kill = &b
	}
	if v := r.FormValue("fast"); v != "" {
		b := v == "true"
		fast = &b
	}
	a.form("/", "dashboard", func(*http.Request) error { return a.d.SetGlobal(kill, fast) })(w, r)
}

// --- egresses ---

func (a *Admin) addEgress(w http.ResponseWriter, r *http.Request) {
	a.form("/egresses", "egresses", func(r *http.Request) error {
		if err := r.ParseMultipartForm(1 << 20); err != nil && !errors.Is(err, http.ErrNotMultipart) {
			return err
		}
		text := r.FormValue("config")
		if f, _, err := r.FormFile("file"); err == nil {
			defer func() { _ = f.Close() }()
			b, err := io.ReadAll(io.LimitReader(f, 64<<10))
			if err != nil {
				return err
			}
			text = string(b)
		}
		res := config.ResolveFamily(r.FormValue("resolve"))
		return a.d.AddEgress(strings.TrimSpace(r.FormValue("name")), text, daemon.EgressOptions{Resolve: &res})
	})(w, r)
}

func (a *Admin) updateEgress(w http.ResponseWriter, r *http.Request) {
	a.form("/egresses", "egresses", func(r *http.Request) error {
		// forms send only the fields they show; absent fields stay unchanged
		var o daemon.EgressOptions
		if v := r.FormValue("enabled"); v != "" {
			b := v == "true"
			o.Enabled = &b
		}
		if v := r.FormValue("weight"); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil {
				return err
			}
			o.Weight = &n
		}
		if v := r.FormValue("resolve"); v != "" {
			res := config.ResolveFamily(v)
			o.Resolve = &res
		}
		return a.d.UpdateEgress(r.PathValue("name"), o)
	})(w, r)
}

func (a *Admin) moveEgress(w http.ResponseWriter, r *http.Request) {
	a.form("/egresses", "egresses", func(r *http.Request) error {
		var names []string
		for _, e := range a.d.Config().SortedEgresses() {
			names = append(names, e.Name)
		}
		i := slices.Index(names, r.PathValue("name"))
		j := i - 1
		if r.FormValue("dir") == "down" {
			j = i + 1
		}
		if i < 0 || j < 0 || j >= len(names) {
			return nil
		}
		names[i], names[j] = names[j], names[i]
		return a.d.OrderEgresses(names)
	})(w, r)
}

// --- clients ---

func parseDate(v string) (*time.Time, error) {
	if v == "" {
		return nil, nil
	}
	t, err := time.ParseInLocation("2006-01-02", v, time.Local)
	if err != nil {
		return nil, err
	}
	t = t.Add(24 * time.Hour) // valid through the given day
	return &t, nil
}

func (a *Admin) addClient(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.FormValue("name"))
	err := func() error {
		exp, err := parseDate(r.FormValue("expires"))
		if err != nil {
			return err
		}
		text, err := a.d.AddClient(name, daemon.ClientOptions{Expires: exp})
		if err == nil {
			a.issued(w, r, name, text, false)
		}
		return err
	}()
	if err != nil {
		a.form("/clients", "clients", func(*http.Request) error { return err })(w, r)
	}
}

func (a *Admin) renewClient(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	text, err := a.d.RenewClient(name)
	if err != nil {
		a.form("/clients/"+name, "clients", func(*http.Request) error { return err })(w, r)
		return
	}
	a.issued(w, r, name, text, true)
}

// issued shows a new client config once: QR code and download. The private
// key is not stored, so this page cannot be opened again later.
func (a *Admin) issued(w http.ResponseWriter, r *http.Request, name, text string, renewed bool) {
	p := a.basePage(r, "nav.clients")
	p.Path = "/clients"
	svg, err := qr.SVG(text)
	if err != nil {
		p.Error = err.Error()
	}
	w.Header().Set("Cache-Control", "no-store")
	p.Data = issuedPage{Name: name, Config: text, Renewed: renewed,
		QR:       template.HTML(svg), // generated by package qr, contains no user input
		Download: template.URL("data:text/plain;charset=utf-8;base64," + base64.StdEncoding.EncodeToString([]byte(text)))}
	a.r.Page(w, "issued", p)
}

type issuedPage struct {
	Name     string
	Config   string
	QR       template.HTML
	Download template.URL // data: URL, nothing is fetched again
	Renewed  bool
}

// security renders the host exposure check; loaded lazily by the
// dashboard because it scans /proc.
func (a *Admin) security(w http.ResponseWriter, r *http.Request) {
	p := a.basePage(r, "nav.dashboard")
	p.Data = securityData{Security: a.d.Security(), ListenPort: a.d.Config().Server.ListenPort}
	html, err := a.r.Fragment("dashboard", "security", p)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_, _ = io.WriteString(w, html)
}

type securityData struct {
	daemon.Security
	ListenPort uint16
}

type clientPage struct {
	Client      daemon.ClientStatus
	Egresses    []config.Egress
	Strategy    config.Strategy // global strategy, shown for "automatic"
	AllowDirect bool
}

func (a *Admin) client(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	var cs daemon.ClientStatus
	found := false
	for _, c := range a.d.Status().Clients {
		if c.Name == name {
			cs, found = c, true
		}
	}
	if !found {
		http.NotFound(w, r)
		return
	}
	p := a.basePage(r, "nav.clients")
	p.Path = "/clients"
	c := a.d.Config()
	p.Data = clientPage{cs, c.SortedEgresses(), c.Selection.Strategy, c.Server.AllowDirect}
	a.r.Page(w, "client", p)
}

func (a *Admin) updateClient(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	a.form("/clients/"+name, "clients", func(r *http.Request) error {
		enabled := r.FormValue("enabled") == "true"
		exp, err := parseDate(r.FormValue("expires"))
		if err != nil {
			return err
		}
		o := daemon.ClientOptions{Enabled: &enabled, Expires: exp, NoExpiry: exp == nil}
		// one "connection" choice: auto, a fixed egress or direct; direct is
		// the client's direct switch, so the egress choice stays untouched
		direct := false
		switch kind, val, _ := strings.Cut(r.FormValue("route"), ":"); kind {
		case "direct":
			direct = true
		case "egress":
			s := config.StrategyFixed
			o.Strategy, o.Fixed = &s, &val
		case "strategy": // explicit failover/weighted set via CLI: keep
			s := config.Strategy(val)
			o.Strategy = &s
		default:
			var s config.Strategy
			empty := ""
			o.Strategy, o.Fixed = &s, &empty
		}
		if err := a.d.UpdateClient(name, o); err != nil {
			return err
		}
		return a.d.SetClientSwitch(name, config.ActionFast, direct)
	})(w, r)
}

func (a *Admin) clientSwitch(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	a.form("/clients/"+name, "clients", func(r *http.Request) error {
		return a.d.SetClientSwitch(name, config.PortalAction(r.FormValue("action")), r.FormValue("on") == "true")
	})(w, r)
}

// --- settings ---

// uploadTLS installs an uploaded or pasted PEM certificate and key.
func (a *Admin) uploadTLS(r *http.Request) error {
	if err := r.ParseMultipartForm(1 << 20); err != nil && !errors.Is(err, http.ErrNotMultipart) {
		return err
	}
	read := func(field string) ([]byte, error) {
		if f, _, err := r.FormFile(field + "_file"); err == nil {
			defer func() { _ = f.Close() }()
			return io.ReadAll(io.LimitReader(f, 256<<10))
		}
		return []byte(strings.TrimSpace(r.FormValue(field))), nil
	}
	cert, err := read("cert")
	if err != nil {
		return err
	}
	key, err := read("key")
	if err != nil {
		return err
	}
	return a.d.InstallTLS(cert, key)
}

func (a *Admin) saveSettings(r *http.Request) error {
	c := a.d.Config()
	actions := make([]string, len(c.Web.Portal.Actions))
	for i, x := range c.Web.Portal.Actions {
		actions[i] = string(x)
	}
	current := map[string]string{
		"strategy":         string(c.Selection.Strategy),
		"fixed":            c.Selection.Fixed,
		"offline":          string(c.Selection.Offline),
		"allow_direct":     strconv.FormatBool(c.Server.AllowDirect),
		"endpoint":         c.Server.Endpoint,
		"resolver":         c.DNS.Resolver.String(),
		"hostnames":        strings.Join(c.Web.Hostnames, ", "),
		"portal_actions":   strings.Join(actions, ", "),
		"admin_interfaces": strings.Join(c.Server.AdminInterfaces, ", "),
		"lockdown_ssh":     strconv.FormatBool(c.Server.LockdownSSH),
		"language":         c.Web.Language,
	}
	// order matters: allow_direct before offline, fixed before strategy
	order := []string{"allow_direct", "fixed", "strategy", "offline", "endpoint", "resolver", "hostnames",
		"portal_actions", "admin_interfaces", "lockdown_ssh", "language"}
	var errs []error
	for _, k := range order {
		v := strings.TrimSpace(r.FormValue(k))
		switch k {
		case "allow_direct", "lockdown_ssh":
			v = strconv.FormatBool(v == "true")
		case "portal_actions": // one checkbox per action
			v = strings.Join(r.Form["portal_actions"], ", ")
		}
		if v == current[k] {
			continue
		}
		if err := a.d.Set(k, v); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", k, err))
		}
	}
	return errors.Join(errs...)
}

func remoteHost(r *http.Request) string {
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return h
}
