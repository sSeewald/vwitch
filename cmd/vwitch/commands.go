package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/sseewald/vwitch/internal/api"
	"github.com/sseewald/vwitch/internal/config"
	"github.com/sseewald/vwitch/internal/daemon"
	"github.com/sseewald/vwitch/internal/i18n"
	"github.com/sseewald/vwitch/internal/qr"
)

func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func onOff(arg string) (bool, error) {
	switch strings.ToLower(arg) {
	case "on", "true", "1", "yes":
		return true, nil
	case "off", "false", "0", "no":
		return false, nil
	}
	return false, fmt.Errorf("expected on or off, got %q", arg)
}

func ageString(sec float64) string {
	if sec < 0 {
		return "never"
	}
	return (time.Duration(sec) * time.Second).String()
}

// --- status ---

func statusCmd(g *globals) *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show egresses, clients and switches",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			var st daemon.Status
			if err := g.client().Do("GET", "/v1/status", nil, &st); err != nil {
				return err
			}
			if g.json {
				return printJSON(st)
			}
			fmt.Printf("vwitch %s · strategy %s · offline %s · kill switch %v · direct mode %v\n\n",
				st.Version, st.Selection.Strategy, st.Selection.Offline, st.Switches.KillSwitch, st.Switches.Fast)
			w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "EGRESS\tSTATE\tPRIO\tWEIGHT\tHANDSHAKE\tLATENCY\tCLIENTS\tENDPOINT")
			for _, e := range st.Egresses {
				state := "down"
				switch {
				case !e.Enabled:
					state = "disabled"
				case e.Healthy:
					state = "up"
				}
				fmt.Fprintf(w, "%s\t%s\t%d\t%d\t%s\t%.0fms\t%d\t%s\n", e.Name, state, e.Priority, e.Weight,
					ageString(e.HandshakeAge), e.LatencyMs, e.Clients, e.Endpoint)
			}
			if err := w.Flush(); err != nil {
				return err
			}
			fmt.Println()
			w = tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "CLIENT\tADDRESS\tONLINE\tEGRESS\tREASON")
			for _, c := range st.Clients {
				exit := c.Exit
				if exit == "egress" {
					exit = c.Egress
				}
				if !c.Active {
					exit = "inactive"
				}
				reason := ""
				if c.Reason != "" {
					reason = i18n.T("en", "reason."+c.Reason)
				}
				fmt.Fprintf(w, "%s\t%s\t%v\t%s\t%s\n", c.Name, c.Address, c.Online, exit, reason)
			}
			return w.Flush()
		},
	}
}

// --- egress ---

func egressCmd(g *globals) *cobra.Command {
	cmd := &cobra.Command{Use: "egress", Aliases: []string{"exit"}, Short: "Manage WireGuard egresses"}

	var opts struct {
		priority, weight int
		resolve          string
		tags             []string
	}
	add := &cobra.Command{
		Use:   "add <name> <wg-config-file|->",
		Short: "Import a WireGuard client config as egress",
		Args:  cobra.ExactArgs(2),
		RunE: func(c *cobra.Command, args []string) error {
			text, err := readFileOrStdin(args[1])
			if err != nil {
				return err
			}
			o := daemon.EgressOptions{}
			if c.Flags().Changed("priority") {
				o.Priority = &opts.priority
			}
			if c.Flags().Changed("weight") {
				o.Weight = &opts.weight
			}
			if c.Flags().Changed("resolve") {
				r := config.ResolveFamily(opts.resolve)
				o.Resolve = &r
			}
			if c.Flags().Changed("tags") {
				o.Tags = &opts.tags
			}
			return g.client().Do("POST", "/v1/egresses", api.AddEgressRequest{Name: args[0], Config: text, Opts: o}, nil)
		},
	}
	add.Flags().IntVar(&opts.priority, "priority", 0, "failover priority, lower is preferred")
	add.Flags().IntVar(&opts.weight, "weight", 1, "weight for strategy weighted")
	add.Flags().StringVar(&opts.resolve, "resolve", "any", "endpoint resolution: any, ipv4, ipv6")
	add.Flags().StringSliceVar(&opts.tags, "tags", nil, "tags, e.g. home,fast")

	set := &cobra.Command{
		Use:   "set <name>",
		Short: "Change priority, weight, resolve or tags",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			o := daemon.EgressOptions{}
			if c.Flags().Changed("priority") {
				o.Priority = &opts.priority
			}
			if c.Flags().Changed("weight") {
				o.Weight = &opts.weight
			}
			if c.Flags().Changed("resolve") {
				r := config.ResolveFamily(opts.resolve)
				o.Resolve = &r
			}
			if c.Flags().Changed("tags") {
				o.Tags = &opts.tags
			}
			return g.client().Do("PATCH", "/v1/egresses/"+args[0], o, nil)
		},
	}
	set.Flags().AddFlagSet(add.Flags())

	enable := func(use string, on bool) *cobra.Command {
		return &cobra.Command{Use: use + " <name>", Short: use + " an egress", Args: cobra.ExactArgs(1),
			RunE: func(_ *cobra.Command, args []string) error {
				return g.client().Do("PATCH", "/v1/egresses/"+args[0], daemon.EgressOptions{Enabled: &on}, nil)
			}}
	}
	cmd.AddCommand(
		&cobra.Command{Use: "list", Aliases: []string{"ls"}, Short: "List egresses", Args: cobra.NoArgs,
			RunE: func(*cobra.Command, []string) error { return statusCmd(g).RunE(nil, nil) }},
		add, set, enable("enable", true), enable("disable", false),
		&cobra.Command{Use: "rm <name>", Aliases: []string{"remove"}, Short: "Remove an egress", Args: cobra.ExactArgs(1),
			RunE: func(_ *cobra.Command, args []string) error {
				return g.client().Do("DELETE", "/v1/egresses/"+args[0], nil, nil)
			}},
		&cobra.Command{Use: "order <name>...", Short: "Set the failover order (first is preferred)", Args: cobra.MinimumNArgs(1),
			RunE: func(_ *cobra.Command, args []string) error {
				return g.client().Do("POST", "/v1/egresses/order", api.OrderRequest{Names: args}, nil)
			}},
	)
	return cmd
}

// --- client ---

func clientCmd(g *globals) *cobra.Command {
	cmd := &cobra.Command{Use: "client", Short: "Manage AmneziaWG clients"}
	var expires, strategy, fixed string
	var showQR bool
	clientOpts := func(c *cobra.Command) (daemon.ClientOptions, error) {
		o := daemon.ClientOptions{}
		if c.Flags().Changed("expires") {
			if expires == "" || expires == "never" {
				o.NoExpiry = true
			} else {
				t, err := time.ParseInLocation("2006-01-02", expires, time.Local)
				if err != nil {
					return o, fmt.Errorf("--expires: use YYYY-MM-DD")
				}
				t = t.Add(24 * time.Hour)
				o.Expires = &t
			}
		}
		if c.Flags().Changed("strategy") {
			s := config.Strategy(strategy)
			o.Strategy = &s
		}
		if c.Flags().Changed("fixed") {
			o.Fixed = &fixed
		}
		return o, nil
	}
	add := &cobra.Command{
		Use:   "add <name>",
		Short: "Create a client and print its config",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			o, err := clientOpts(c)
			if err != nil {
				return err
			}
			var out api.TextResponse
			if err := g.client().Do("POST", "/v1/clients", api.AddClientRequest{Name: args[0], Opts: o}, &out); err != nil {
				return err
			}
			return printConfig(out.Text, showQR)
		},
	}
	set := &cobra.Command{
		Use:   "set <name>",
		Short: "Change expiry or strategy",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			o, err := clientOpts(c)
			if err != nil {
				return err
			}
			return g.client().Do("PATCH", "/v1/clients/"+args[0], o, nil)
		},
	}
	for _, c := range []*cobra.Command{add, set} {
		c.Flags().StringVar(&expires, "expires", "", "last valid day YYYY-MM-DD, or never")
		c.Flags().StringVar(&strategy, "strategy", "", "override: failover, weighted, fixed (empty: global)")
		c.Flags().StringVar(&fixed, "fixed", "", "egress for strategy fixed")
	}
	add.Flags().BoolVar(&showQR, "qr", false, "also print a QR code")

	renew := &cobra.Command{
		Use:   "renew <name>",
		Short: "Create a new config with new keys (the old one stops working)",
		Long: "The private key of a client is never stored, so its config is shown only once.\n" +
			"renew replaces lost or outdated configs.",
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			var out api.TextResponse
			if err := g.client().Do("POST", "/v1/clients/"+args[0]+"/renew", nil, &out); err != nil {
				return err
			}
			return printConfig(out.Text, showQR)
		},
	}
	renew.Flags().BoolVar(&showQR, "qr", false, "also print a QR code")
	enable := func(use string, on bool) *cobra.Command {
		return &cobra.Command{Use: use + " <name>", Short: use + " a client", Args: cobra.ExactArgs(1),
			RunE: func(_ *cobra.Command, args []string) error {
				return g.client().Do("PATCH", "/v1/clients/"+args[0], daemon.ClientOptions{Enabled: &on}, nil)
			}}
	}
	cmd.AddCommand(
		&cobra.Command{Use: "list", Aliases: []string{"ls"}, Short: "List clients", Args: cobra.NoArgs,
			RunE: func(*cobra.Command, []string) error { return statusCmd(g).RunE(nil, nil) }},
		add, set, renew, enable("enable", true), enable("disable", false),
		&cobra.Command{Use: "rm <name>", Aliases: []string{"remove"}, Short: "Remove a client (offboarding)", Args: cobra.ExactArgs(1),
			RunE: func(_ *cobra.Command, args []string) error {
				return g.client().Do("DELETE", "/v1/clients/"+args[0], nil, nil)
			}},
		&cobra.Command{Use: "switch <name> <fast|block|direct> <on|off>", Short: "Set a client's own switch", Args: cobra.ExactArgs(3),
			RunE: func(_ *cobra.Command, args []string) error {
				on, err := onOff(args[2])
				if err != nil {
					return err
				}
				return g.client().Do("POST", "/v1/clients/"+args[0]+"/switch",
					api.ClientSwitchRequest{Action: config.PortalAction(args[1]), On: on}, nil)
			}},
	)
	return cmd
}

func printConfig(text string, withQR bool) error {
	fmt.Print(text)
	if withQR {
		s, err := qr.Terminal(text)
		if err != nil {
			return err
		}
		fmt.Print("\n" + s)
	}
	return nil
}

// --- switches and settings ---

func switchCmd(g *globals, use, field, short string) *cobra.Command {
	return &cobra.Command{
		Use:       use + " <on|off>",
		Short:     short,
		Args:      cobra.ExactArgs(1),
		ValidArgs: []string{"on", "off"},
		RunE: func(_ *cobra.Command, args []string) error {
			on, err := onOff(args[0])
			if err != nil {
				return err
			}
			req := api.SwitchRequest{}
			if field == "kill_switch" {
				req.KillSwitch = &on
			} else {
				req.Fast = &on
			}
			return g.client().Do("POST", "/v1/switches", req, nil)
		},
	}
}

func setCmd(g *globals) *cobra.Command {
	return &cobra.Command{
		Use:   "set <key> <value>",
		Short: "Change a setting (" + strings.Join(daemon.SettingKeys, ", ") + ")",
		Args:  cobra.ExactArgs(2),
		RunE: func(_ *cobra.Command, args []string) error {
			return g.client().Do("POST", "/v1/settings", api.SetRequest{Key: args[0], Value: args[1]}, nil)
		},
	}
}

func reloadCmd(g *globals) *cobra.Command {
	return &cobra.Command{
		Use:   "reload",
		Short: "Re-read vwitch.yaml after manual edits",
		Args:  cobra.NoArgs,
		RunE:  func(*cobra.Command, []string) error { return g.client().Do("POST", "/v1/reload", nil, nil) },
	}
}

func configCmd(g *globals) *cobra.Command {
	cmd := &cobra.Command{Use: "config", Short: "Inspect the configuration file"}
	cmd.AddCommand(&cobra.Command{
		Use:   "validate [file]",
		Short: "Check a configuration file",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			path := g.config
			if len(args) == 1 {
				path = args[0]
			}
			if _, err := config.Open(path); err != nil {
				return err
			}
			fmt.Println(path, "is valid")
			return nil
		},
	})
	return cmd
}

func adminCmd(g *globals) *cobra.Command {
	cmd := &cobra.Command{Use: "admin", Short: "Admin UI access"}
	var fromStdin bool
	passwd := &cobra.Command{
		Use:   "passwd",
		Short: "Set the admin UI password",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			pw, err := readPassword(fromStdin)
			if err != nil {
				return err
			}
			return g.client().Do("POST", "/v1/password", api.PasswordRequest{Password: pw}, nil)
		},
	}
	passwd.Flags().BoolVar(&fromStdin, "stdin", false, "read the password from stdin")
	cmd.AddCommand(passwd)
	return cmd
}

func tlsCmd(g *globals) *cobra.Command {
	cmd := &cobra.Command{Use: "tls", Short: "Admin UI certificate (HTTPS only; applies immediately)"}
	cmd.AddCommand(
		&cobra.Command{Use: "set <cert.pem> <key.pem>", Short: "Install a PEM certificate and key", Args: cobra.ExactArgs(2),
			RunE: func(_ *cobra.Command, args []string) error {
				cert, err := os.ReadFile(args[0])
				if err != nil {
					return err
				}
				key, err := os.ReadFile(args[1])
				if err != nil {
					return err
				}
				return g.client().Do("POST", "/v1/tls", api.TLSRequest{Cert: string(cert), Key: string(key)}, nil)
			}},
		&cobra.Command{Use: "clear", Short: "Replace the certificate with a new self-signed one", Args: cobra.NoArgs,
			RunE: func(*cobra.Command, []string) error {
				return g.client().Do("POST", "/v1/tls", api.TLSRequest{}, nil)
			}},
	)
	return cmd
}

// --- helpers ---

func readFileOrStdin(path string) (string, error) {
	var r io.Reader = os.Stdin
	if path != "-" {
		f, err := os.Open(path)
		if err != nil {
			return "", err
		}
		defer func() { _ = f.Close() }()
		r = f
	}
	b, err := io.ReadAll(io.LimitReader(r, 64<<10))
	return string(b), err
}

func readPassword(fromStdin bool) (string, error) {
	if fromStdin || !term.IsTerminal(int(os.Stdin.Fd())) {
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return "", err
		}
		return strings.TrimRight(line, "\r\n"), nil
	}
	fmt.Fprint(os.Stderr, "New password: ")
	a, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	fmt.Fprint(os.Stderr, "Repeat: ")
	b, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	if string(a) != string(b) {
		return "", errors.New("passwords do not match")
	}
	return string(a), nil
}
