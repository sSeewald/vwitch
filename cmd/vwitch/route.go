package main

import (
	"fmt"
	"os"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/sseewald/vwitch/internal/api"
	"github.com/sseewald/vwitch/internal/daemon"
)

func routeCmd(g *globals) *cobra.Command {
	cmd := &cobra.Command{Use: "route", Aliases: []string{"routes"},
		Short: "Send domains through a fixed egress",
		Long: "Domain routes send the listed domains, including all subdomains, through one\n" +
			"egress. vwitch learns their addresses from the clients' DNS queries. If the\n" +
			"egress is down, the client's normal exit applies; the kill switch and blocked\n" +
			"clients always win."}

	routes := func() ([]daemon.RouteStatus, error) {
		var st daemon.Status
		err := g.client().Do("GET", "/v1/status", nil, &st)
		return st.Routes, err
	}
	find := func(name string) (*daemon.RouteStatus, error) {
		rs, err := routes()
		if err != nil {
			return nil, err
		}
		for i := range rs {
			if rs[i].Name == name {
				return &rs[i], nil
			}
		}
		return nil, nil
	}
	put := func(name, egress string, domains []string) error {
		return g.client().Do("PUT", "/v1/routes/"+name, api.RouteRequest{Egress: egress, Domains: domains}, nil)
	}

	var via string
	set := &cobra.Command{
		Use:   "set <name> --via <egress> <domain>...",
		Short: "Create a route or replace its egress and domains",
		Args:  cobra.MinimumNArgs(2),
		RunE: func(_ *cobra.Command, args []string) error {
			if via == "" {
				return fmt.Errorf("--via <egress> is required")
			}
			return put(args[0], via, args[1:])
		},
	}
	set.Flags().StringVar(&via, "via", "", "target egress")

	add := &cobra.Command{
		Use:   "add <name> <domain>... [--via <egress>]",
		Short: "Add domains to a route (creates it with --via)",
		Args:  cobra.MinimumNArgs(2),
		RunE: func(_ *cobra.Command, args []string) error {
			r, err := find(args[0])
			if err != nil {
				return err
			}
			egress, domains := via, args[1:]
			if r != nil {
				domains = append(slices.Clone(r.Domains), domains...)
				if egress == "" {
					egress = r.Egress
				}
			}
			if egress == "" {
				return fmt.Errorf("route %q does not exist yet: pass --via <egress>", args[0])
			}
			return put(args[0], egress, domains)
		},
	}
	add.Flags().StringVar(&via, "via", "", "target egress")

	rm := &cobra.Command{
		Use:     "rm <name> [domain...]",
		Aliases: []string{"remove"},
		Short:   "Remove a route, or only some of its domains",
		Args:    cobra.MinimumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if len(args) == 1 {
				return g.client().Do("DELETE", "/v1/routes/"+args[0], nil, nil)
			}
			r, err := find(args[0])
			if err != nil {
				return err
			}
			if r == nil {
				return fmt.Errorf("unknown route %q", args[0])
			}
			drop, err := daemon.NormalizeDomains(args[1:])
			if err != nil {
				return err
			}
			keep := slices.DeleteFunc(slices.Clone(r.Domains), func(d string) bool { return slices.Contains(drop, d) })
			if len(keep) == 0 {
				return g.client().Do("DELETE", "/v1/routes/"+args[0], nil, nil)
			}
			return put(args[0], r.Egress, keep)
		},
	}

	list := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List routes",
		Args:    cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			rs, err := routes()
			if err != nil {
				return err
			}
			if g.json {
				return printJSON(rs)
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "ROUTE\tVIA\tSTATE\tLEARNED\tDOMAINS")
			for _, r := range rs {
				state := "active"
				if !r.Active {
					state = "egress down, normal exit"
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%s\n", r.Name, r.Egress, state, r.Learned, strings.Join(r.Domains, ", "))
			}
			return tw.Flush()
		},
	}
	cmd.AddCommand(list, set, add, rm)
	return cmd
}
