package main

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sseewald/vwitch/internal/api"
)

func blockCmd(g *globals) *cobra.Command {
	cmd := &cobra.Command{Use: "block", Short: "Block domains and countries",
		Long: "Blocked domains (with all subdomains) are answered with 0.0.0.0 by vwitch's DNS.\n" +
			"Countries are blocked or allowed with:\n" +
			"  vwitch set regions.countries RU,BY\n  vwitch set regions.mode block|allow\n" +
			"  vwitch set regions.direction both|outgoing|incoming\n  vwitch set regions.enabled true"}
	change := func(remove bool) func(*cobra.Command, []string) error {
		return func(_ *cobra.Command, args []string) error {
			return g.client().Do("POST", "/v1/blocking/domains", api.BlockDomainsRequest{Domains: args, Remove: remove}, nil)
		}
	}
	get := func() (api.BlockingResponse, error) {
		var r api.BlockingResponse
		return r, g.client().Do("GET", "/v1/blocking", nil, &r)
	}
	cmd.AddCommand(
		&cobra.Command{Use: "add <domain>...", Short: "Block domains", Args: cobra.MinimumNArgs(1), RunE: change(false)},
		&cobra.Command{Use: "rm <domain>...", Aliases: []string{"remove"}, Short: "Unblock domains", Args: cobra.MinimumNArgs(1), RunE: change(true)},
		&cobra.Command{Use: "list", Short: "Show blocked domains and countries", Args: cobra.NoArgs,
			RunE: func(*cobra.Command, []string) error {
				r, err := get()
				if err != nil {
					return err
				}
				fmt.Printf("Domains: %s\n", orNone(strings.Join(r.Domains, ", ")))
				rg := r.Regions
				state := "off"
				if rg.Active() {
					state = fmt.Sprintf("%s %s (%s)", rg.Mode, strings.Join(rg.Countries, ", "), rg.Direction)
				}
				fmt.Printf("Countries: %s\n", state)
				if rg.Active() {
					switch {
					case r.Geo.Busy:
						fmt.Println("Country data: downloading")
					case r.Geo.Ranges > 0:
						fmt.Printf("Country data: %d ranges from %s\n", r.Geo.Ranges, r.Geo.Updated.Format("2006-01-02"))
					}
					if r.Geo.Error != "" {
						fmt.Printf("Country data error: %s\n", r.Geo.Error)
					}
				}
				return nil
			}},
		&cobra.Command{Use: "log", Short: "Show the latest blocked lookups and connections", Args: cobra.NoArgs,
			RunE: func(*cobra.Command, []string) error {
				r, err := get()
				if err != nil {
					return err
				}
				for _, e := range r.Log {
					what, dir := e.Domain, "→"
					if e.Addr.IsValid() {
						what = fmt.Sprintf("%s %s/%d", e.Addr, e.Proto, e.Port)
						if e.Country != "" {
							what += " (" + e.Country + ")"
						}
						if e.Domain != "" {
							what += " " + e.Domain
						}
					}
					if e.Incoming {
						dir = "←"
					}
					fmt.Printf("%s  %s %-10s %s  [%s]\n", e.Time.Local().Format("02.01. 15:04:05"), dir, orNone(e.Client), what, e.Source)
				}
				return nil
			}},
	)
	return cmd
}

func orNone(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
