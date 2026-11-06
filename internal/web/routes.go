package web

import (
	"fmt"
	"net/http"
	"strings"
)

// routesPage is the data of the domain routes page. Draft keeps the input of
// a form that failed validation, so nothing typed gets lost.
type routesPage struct {
	pageData
	Draft routeDraft
}

type routeDraft struct {
	For     string // "" = add form, else the route being edited
	Name    string
	Egress  string
	Domains string
}

// splitDomains accepts one domain per line, or separated by commas/spaces.
func splitDomains(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool {
		return r == '\n' || r == '\r' || r == ',' || r == ' ' || r == '\t' || r == ';'
	})
}

func (a *Admin) routesData() routesPage { return routesPage{pageData: a.data()} }

func (a *Admin) routes(w http.ResponseWriter, r *http.Request) {
	p := a.basePage(r, "nav.routes")
	p.Data = a.routesData()
	a.r.Page(w, "routes", p)
}

// saveRoute handles both the add form (no {name}) and the edit forms.
func (a *Admin) saveRoute(w http.ResponseWriter, r *http.Request) {
	editing := r.PathValue("name")
	d := routeDraft{For: editing, Name: strings.TrimSpace(r.FormValue("name")),
		Egress: r.FormValue("egress"), Domains: r.FormValue("domains")}
	if editing != "" {
		d.Name = editing
	}
	err := func() error {
		if _, exists := a.d.Config().Route(d.Name); editing == "" && exists {
			return fmt.Errorf("route %q already exists", d.Name)
		}
		return a.d.SetRoute(d.Name, d.Egress, splitDomains(d.Domains))
	}()
	a.routesResult(w, r, err, d)
}

func (a *Admin) deleteRoute(w http.ResponseWriter, r *http.Request) {
	a.routesResult(w, r, a.d.RemoveRoute(r.PathValue("name")), routeDraft{})
}

// routesResult redirects back after success or shows the page with the error.
func (a *Admin) routesResult(w http.ResponseWriter, r *http.Request, err error, d routeDraft) {
	if err == nil {
		http.Redirect(w, r, "/routes", http.StatusSeeOther)
		return
	}
	p := a.basePage(r, "nav.routes")
	p.Path = "/routes"
	p.Error = err.Error()
	data := a.routesData()
	data.Draft = d
	p.Data = data
	a.r.Page(w, "routes", p)
}
