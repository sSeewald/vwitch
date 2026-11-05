// Command vwitch is the daemon and the admin CLI of vwitch.
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/sseewald/vwitch/internal/api"
	"github.com/sseewald/vwitch/internal/config"
	"github.com/sseewald/vwitch/internal/version"
)

type globals struct {
	config string
	socket string
	json   bool
}

func main() {
	g := &globals{}
	root := &cobra.Command{
		Use:           "vwitch",
		Short:         "Egress switch for an AmneziaWG relay",
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       version.String(),
	}
	root.PersistentFlags().StringVar(&g.config, "config", config.DefaultPath, "configuration file")
	root.PersistentFlags().StringVar(&g.socket, "socket", config.DefaultSocket, "API socket of the running daemon")
	root.PersistentFlags().BoolVar(&g.json, "json", false, "JSON output where supported")
	root.AddCommand(
		serveCmd(g), setupCmd(g), doctorCmd(g), statusCmd(g), egressCmd(g), clientCmd(g),
		switchCmd(g, "killswitch", "kill_switch", "Block all client traffic immediately"),
		switchCmd(g, "fast", "fast", "Send all clients through the server's own uplink"),
		setCmd(g), configCmd(g), reloadCmd(g), adminCmd(g), tlsCmd(g), cloudInitCmd(),
	)
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func (g *globals) client() *api.Client { return api.NewClient(g.socket) }
