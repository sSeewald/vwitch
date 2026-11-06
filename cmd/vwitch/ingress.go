package main

import (
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/sseewald/vwitch/internal/api"
	"github.com/sseewald/vwitch/internal/daemon"
)

func ingressCmd(g *globals) *cobra.Command {
	cmd := &cobra.Command{Use: "ingress", Aliases: []string{"ingresses"},
		Short: "Manage AmneziaWG ingresses (the interfaces clients connect to)",
		Long: "Each ingress is an AmneziaWG interface with its own UDP port and camouflage.\n" +
			"All ingresses share the client network, the server address and the server key.\n" +
			"A strict ingress accepts only AWG 3.1 clients; an isolated one keeps its\n" +
			"clients apart from all other clients."}

	var (
		port                                     uint16
		strict, isolated, cookies, padding, awg3 bool
	)
	opts := func(c *cobra.Command) daemon.IngressOptions {
		o := daemon.IngressOptions{}
		f := c.Flags()
		if f.Changed("port") {
			o.ListenPort = &port
		}
		for name, dst := range map[string]**bool{"strict": &o.Strict, "isolated": &o.Isolated,
			"padding": &o.ContentPadding, "new-clients-awg3": &o.NewClientsAWG3} {
			if f.Changed(name) {
				v, _ := f.GetBool(name)
				*dst = &v
			}
		}
		if f.Changed("cookies") { // the flag says what is sent, the option what is not
			off := !cookies
			o.DisableCookies = &off
		}
		return o
	}
	flags := func(c *cobra.Command) {
		c.Flags().Uint16Var(&port, "port", 0, "UDP listen port (default: next free port)")
		c.Flags().BoolVar(&strict, "strict", false, "header protection: only AWG 3.1 clients can connect")
		c.Flags().BoolVar(&isolated, "isolated", false, "no traffic between its clients and any other client")
		c.Flags().BoolVar(&cookies, "cookies", true, "send WireGuard cookie replies under load")
		c.Flags().BoolVar(&padding, "padding", false, "random padding of data packets")
		c.Flags().BoolVar(&awg3, "new-clients-awg3", true, "new clients get the AWG 3.1 config by default")
	}

	add := &cobra.Command{
		Use:   "add <name>",
		Short: "Create an ingress with new camouflage parameters",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			return g.client().Do("POST", "/v1/ingresses", api.AddIngressRequest{Name: args[0], Opts: opts(c)}, nil)
		},
	}
	flags(add)
	set := &cobra.Command{
		Use:   "set <name>",
		Short: "Change port, strict, isolated or camouflage options",
		Long:  "A new port or strict mode needs a new config on every client of the ingress.",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			return g.client().Do("PATCH", "/v1/ingresses/"+args[0], opts(c), nil)
		},
	}
	flags(set)

	list := &cobra.Command{Use: "list", Aliases: []string{"ls"}, Short: "List ingresses", Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			var st daemon.Status
			if err := g.client().Do("GET", "/v1/status", nil, &st); err != nil {
				return err
			}
			if g.json {
				return json.NewEncoder(os.Stdout).Encode(st.Ingresses)
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			_, _ = fmt.Fprintln(w, "NAME\tIFACE\tPORT\tMODE\tISOLATED\tADMIN\tCLIENTS\tONLINE")
			for _, in := range st.Ingresses {
				mode := "compatible"
				if in.Strict {
					mode = "strict"
				}
				_, _ = fmt.Fprintf(w, "%s\t%s\t%d\t%s\t%v\t%v\t%d\t%d\n", in.Name, in.Iface, in.Port, mode, in.Isolated, in.Admin, in.Clients, in.Online)
			}
			return w.Flush()
		}}

	cmd.AddCommand(list, add, set,
		&cobra.Command{Use: "rm <name>", Aliases: []string{"remove"}, Short: "Remove an ingress without clients", Args: cobra.ExactArgs(1),
			RunE: func(_ *cobra.Command, args []string) error {
				return g.client().Do("DELETE", "/v1/ingresses/"+args[0], nil, nil)
			}})
	return cmd
}
