package web

import (
	"cmp"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/sseewald/vwitch/internal/activity"
	"github.com/sseewald/vwitch/internal/blocking"
	"github.com/sseewald/vwitch/internal/config"
	"github.com/sseewald/vwitch/internal/daemon"
)

// Pages for blocking (security) and activity (traffic and domains).

const blockLogRows = 200

type securityPage struct {
	Config    *config.Config
	Countries []Country // the picker, sorted by name
	Selected  []Country
	Geo       daemon.GeoStatus
	Log       blockLog
}

type blockLog struct {
	Kind   string // "", "domain" or "address"
	Events []blocking.Event
}

func (a *Admin) securityData(r *http.Request) securityPage {
	l := a.lang(r)
	c := a.d.Config()
	p := securityPage{Config: c, Countries: countries(l), Geo: a.d.Geo(), Log: a.blockLog(r)}
	for _, code := range c.Security.Regions.Countries {
		p.Selected = append(p.Selected, country(l, code))
	}
	return p
}

func (a *Admin) blockLog(r *http.Request) blockLog {
	k := r.URL.Query().Get("log")
	if k != "domain" && k != "address" {
		k = ""
	}
	return blockLog{Kind: k, Events: a.d.BlockLog(blockLogRows, k)}
}

func (a *Admin) securityPage(w http.ResponseWriter, r *http.Request) {
	a.securityResult(w, r, nil)
}

// securityResult shows the page, with the error of a failed change.
func (a *Admin) securityResult(w http.ResponseWriter, r *http.Request, err error) {
	p := a.basePage(r, "nav.security")
	p.Path = "/security"
	if err != nil {
		p.Error = err.Error()
	}
	p.Data = a.securityData(r)
	a.r.Page(w, "security", p)
}

func (a *Admin) securityLog(w http.ResponseWriter, r *http.Request) {
	p := a.basePage(r, "nav.security")
	p.Data = securityPage{Log: a.blockLog(r)}
	a.fragment(w, "security", "block-log", p)
}

func (a *Admin) saveRegions(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		a.securityResult(w, r, err)
		return
	}
	err := a.d.SetMany([][2]string{
		{"regions.mode", r.FormValue("mode")},
		{"regions.direction", r.FormValue("direction")},
		{"regions.countries", strings.Join(r.Form["countries"], ",")},
		{"regions.enabled", strconv.FormatBool(r.FormValue("enabled") == "true")},
	})
	if err != nil {
		a.securityResult(w, r, err)
		return
	}
	savedRedirect(w, r, "/security")
}

// saveDomains takes the kept chips and the newly typed domains.
func (a *Admin) saveDomains(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		a.securityResult(w, r, err)
		return
	}
	keep := r.Form["domains"]
	var drop []string
	for _, d := range a.d.Config().Security.BlockedDomains {
		if !slices.Contains(keep, d) {
			drop = append(drop, d)
		}
	}
	var err error
	if len(drop) > 0 {
		err = a.d.UnblockDomain(drop...)
	}
	if add := splitDomains(r.FormValue("add")); err == nil && len(add) > 0 {
		err = a.d.BlockDomain(add...)
	}
	if err != nil {
		a.securityResult(w, r, err)
		return
	}
	savedRedirect(w, r, "/security")
}

type activityPage struct {
	Config   *config.Config
	Ranges   []activity.Range
	Range    string
	Client   string // "" = all
	Query    string
	Totals   []clientTraffic
	Sum      activity.Counter
	Domains  []activity.DomainStat
	Blocked  map[string]bool // registrable domains on the block list
	RouteOf  map[string]string
	Disabled bool // the domain list is switched off
	Back     string
}

type clientTraffic struct {
	Name    string
	Ingress string // shown when there is more than one
	Bytes   activity.Counter
	Share   float64 // of all bytes, 0..100
}

func (a *Admin) activity(w http.ResponseWriter, r *http.Request) {
	a.activityResult(w, r, nil)
}

func (a *Admin) activityResult(w http.ResponseWriter, r *http.Request, err error) {
	q := r.URL.Query()
	if r.Method == http.MethodPost { // after a failed change: the filters of the page it came from
		if u, ok := activityBack(r.FormValue("back")); ok {
			q = u
		}
	}
	c := a.d.Config()
	rg := activity.RangeByName(q.Get("range"))
	d := activityPage{Config: c, Ranges: activity.Ranges, Range: rg.Name, Client: q.Get("client"),
		Query: strings.TrimSpace(q.Get("q")), Disabled: c.Security.NoActivity,
		Blocked: map[string]bool{}, RouteOf: map[string]string{}}
	if _, ok := c.Client(d.Client); !ok {
		d.Client = ""
	}
	d.Back = "/activity?" + (url.Values{"range": {d.Range}, "client": {d.Client}, "q": {d.Query}}).Encode()

	totals := a.d.TrafficTotals(rg.Name)
	d.Sum = totals[activity.Total]
	all := float64(d.Sum.Down + d.Sum.Up)
	for _, cl := range c.Clients {
		t := clientTraffic{Name: cl.Name, Ingress: cl.Ingress, Bytes: totals[cl.Name]}
		if all > 0 {
			t.Share = float64(t.Bytes.Down+t.Bytes.Up) / all * 100
		}
		d.Totals = append(d.Totals, t)
	}
	slices.SortStableFunc(d.Totals, func(x, y clientTraffic) int {
		return cmp.Compare(y.Bytes.Down+y.Bytes.Up, x.Bytes.Down+x.Bytes.Up)
	})

	for _, s := range c.Security.BlockedDomains {
		d.Blocked[s] = true
	}
	for _, rt := range c.Routes {
		for _, s := range rt.Domains {
			d.RouteOf[s] = rt.Egress
		}
	}
	for _, s := range a.d.Domains(d.Client) {
		if d.Query == "" || strings.Contains(s.Domain, strings.ToLower(d.Query)) {
			d.Domains = append(d.Domains, s)
		}
	}

	p := a.basePage(r, "nav.activity")
	p.Path = "/activity"
	if err != nil {
		p.Error = err.Error()
	}
	p.Data = d
	a.r.Page(w, "activity", p)
}

// activityBack accepts only a link back to the activity page.
func activityBack(s string) (url.Values, bool) {
	path, query, _ := strings.Cut(s, "?")
	if path != "/activity" {
		return nil, false
	}
	v, err := url.ParseQuery(query)
	return v, err == nil
}

func (a *Admin) activityChange(fn func(*http.Request) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := fn(r); err != nil {
			a.activityResult(w, r, err)
			return
		}
		back := "/activity"
		if _, ok := activityBack(r.FormValue("back")); ok {
			back = r.FormValue("back")
		}
		savedRedirect(w, r, back)
	}
}

func (a *Admin) blockToggle(r *http.Request) error {
	d := r.FormValue("domain")
	if r.FormValue("on") == "true" {
		return a.d.BlockDomain(d)
	}
	return a.d.UnblockDomain(d)
}

func (a *Admin) routeDomain(r *http.Request) error {
	return a.d.RouteDomain(r.FormValue("domain"), r.FormValue("egress"))
}

// trafficSeries is the JSON the traffic chart draws.
type trafficSeries struct {
	Step   int64      `json:"step"`   // seconds per point
	Points [][4]int64 `json:"points"` // time, down, up (bytes), blocked events
}

func (a *Admin) traffic(w http.ResponseWriter, r *http.Request) {
	rg, pts := a.d.Traffic(r.URL.Query().Get("range"), r.URL.Query().Get("client"))
	if len(pts) > 1 { // the running bucket is incomplete and would always dip
		pts = pts[:len(pts)-1]
	}
	out := trafficSeries{Step: int64(rg.Step / time.Second), Points: make([][4]int64, len(pts))}
	for i, p := range pts {
		out.Points[i] = [4]int64{p.T, p.Down, p.Up, p.Blocks}
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(out)
}

func (a *Admin) fragment(w http.ResponseWriter, page, block string, p Page) {
	html, err := a.r.Fragment(page, block, p)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = io.WriteString(w, html)
}
