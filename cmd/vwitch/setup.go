package main

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sseewald/vwitch/internal/auth"
	"github.com/sseewald/vwitch/internal/cloudinit"
	"github.com/sseewald/vwitch/internal/config"
	"github.com/sseewald/vwitch/internal/daemon"
	"github.com/sseewald/vwitch/internal/setup"
)

func setupCmd(g *globals) *cobra.Command {
	var o setup.Options
	var endpoint, address, resolver, passwordFile string
	var passwordStdin bool
	cmd := &cobra.Command{
		Use:   "setup",
		Short: "Create the initial configuration (keys, AWG parameters, admin password)",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			if _, err := os.Stat(g.config); err == nil {
				return fmt.Errorf("%s exists; edit it or use 'vwitch set'", g.config)
			}
			o.Endpoint = endpoint
			if endpoint == "" || endpoint == "auto" {
				ip, err := setup.DetectEndpoint()
				if err != nil {
					return fmt.Errorf("detect endpoint: %w (use --endpoint)", err)
				}
				o.Endpoint = ip.String()
				if ip.IsPrivate() {
					fmt.Fprintf(os.Stderr, "warning: %s is a private address; set the public one with 'vwitch set endpoint <host>'\n", ip)
				}
			}
			var err error
			if address != "" {
				if o.Address, err = netip.ParsePrefix(address); err != nil {
					return fmt.Errorf("--address: %w", err)
				}
			}
			if resolver != "" {
				if o.Resolver, err = netip.ParseAddr(resolver); err != nil {
					return fmt.Errorf("--resolver: %w", err)
				}
			}
			if passwordStdin {
				if o.Password, err = readPassword(true); err != nil {
					return err
				}
			}
			c, pw, err := setup.NewConfig(o)
			if err != nil {
				return err
			}
			if _, err := config.Create(g.config, c); err != nil {
				return err
			}
			fmt.Printf("Created %s\n", g.config)
			fmt.Printf("Endpoint: %s:%d · client network %s\n", c.Server.Endpoint, c.Ingresses[0].ListenPort, c.ClientNet())
			switch {
			case pw == "" || passwordStdin:
				fmt.Printf("Admin user: %s, password as given\n", c.Web.Admin.Username)
			case passwordFile != "":
				if err := os.MkdirAll(filepath.Dir(passwordFile), 0o700); err != nil {
					return err
				}
				if err := os.WriteFile(passwordFile, []byte(pw+"\n"), 0o600); err != nil {
					return err
				}
				fmt.Printf("Admin user: %s, password written to %s\n", c.Web.Admin.Username, passwordFile)
			default:
				fmt.Printf("Admin user: %s\nAdmin password: %s\n", c.Web.Admin.Username, pw)
			}
			fmt.Printf("Admin UI: https://<admin interface>%s (allowed: %s)\n", c.Web.Admin.Listen, strings.Join(c.Server.AdminInterfaces, ", "))
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&endpoint, "endpoint", "auto", "public host or IP clients connect to")
	f.Uint16Var(&o.ListenPort, "listen-port", config.DefaultListenPort, "AmneziaWG UDP port")
	f.StringVar(&address, "address", config.DefaultAddress.String(), "server address and client network")
	f.StringVar(&resolver, "resolver", config.DefaultResolver.String(), "public DNS resolver for clients")
	f.BoolVar(&o.AllowDirect, "allow-direct", false, "allow the server's own uplink as egress (direct)")
	f.StringSliceVar(&o.AdminInterfaces, "admin-interfaces", nil, "interfaces allowed to reach the admin UI (default lo,awg0)")
	f.BoolVar(&o.LockdownSSH, "lockdown-ssh", false, "allow SSH only on admin interfaces once they are up")
	f.StringVar(&o.Language, "language", config.DefaultLanguage, "default UI language (en, de)")
	f.StringVar(&o.Username, "admin-user", config.DefaultAdminUser, "admin login name")
	f.StringVar(&passwordFile, "password-file", "", "write the generated admin password to this file instead of printing it")
	f.BoolVar(&passwordStdin, "admin-password-stdin", false, "read the admin password from stdin instead of generating one")
	f.StringVar(&o.PasswordHash, "admin-password-hash", "", "bcrypt hash of the admin password (as written by 'vwitch cloud-init --ask-admin-password')")
	return cmd
}

func doctorCmd(g *globals) *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Check that this host can run vwitch",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			failed := 0
			check := func(name string, err error) {
				if err != nil {
					failed++
					fmt.Printf("✗ %s: %v\n", name, err)
					return
				}
				fmt.Printf("✓ %s\n", name)
			}
			check("linux", func() error {
				if runtime.GOOS != "linux" {
					return errors.New("vwitch serve needs Linux")
				}
				return nil
			}())
			check("root", func() error {
				if os.Geteuid() != 0 {
					return errors.New("run as root")
				}
				return nil
			}())
			check("/dev/net/tun (AmneziaWG userspace)", exists("/dev/net/tun"))
			check("wireguard kernel module (egresses)", func() error {
				if exists("/sys/module/wireguard") == nil {
					return nil
				}
				return errors.New("not loaded; run 'modprobe wireguard' (built into Debian 12+ / Ubuntu 22.04+ kernels)")
			}())
			check("nf_tables", func() error {
				if exists("/sys/module/nf_tables") == nil || exists("/proc/net/nf_conntrack") == nil {
					return nil
				}
				return errors.New("nftables kernel support not loaded")
			}())
			check("ip forwarding", func() error {
				b, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
				if err != nil || strings.TrimSpace(string(b)) != "1" {
					return errors.New("off (vwitch enables it when running)")
				}
				return nil
			}())
			check("configuration "+g.config, func() error { _, err := config.Open(g.config); return err }())
			var st daemon.Status
			check("daemon", g.client().Do("GET", "/v1/status", nil, &st))
			if failed > 0 {
				return fmt.Errorf("%d check(s) failed", failed)
			}
			return nil
		},
	}
}

func exists(p string) error {
	_, err := os.Stat(p)
	return err
}

func cloudInitCmd() *cobra.Command {
	var v cloudinit.Vars
	var address, resolver string
	var egresses []string
	var askPassword bool
	cmd := &cobra.Command{
		Use:   "cloud-init",
		Short: "Print cloud-init user data that installs and configures vwitch",
		Long: "Print cloud-init user data for a fresh Debian/Ubuntu VPS.\n\n" +
			"Example:\n  vwitch cloud-init --endpoint vpn.example.org --allow-direct \\\n" +
			"    --netbird-setup-key XXXX --lockdown-ssh --egress home=./home.conf:ipv6 > user-data.yaml",
		Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			var err error
			if address != "" {
				if v.Address, err = netip.ParsePrefix(address); err != nil {
					return fmt.Errorf("--address: %w", err)
				}
			}
			if resolver != "" {
				if v.Resolver, err = netip.ParseAddr(resolver); err != nil {
					return fmt.Errorf("--resolver: %w", err)
				}
			}
			for _, spec := range egresses {
				name, rest, ok := strings.Cut(spec, "=")
				if !ok {
					return fmt.Errorf("--egress %q: use name=file[:any|ipv4|ipv6]", spec)
				}
				file, res, _ := strings.Cut(rest, ":")
				text, err := os.ReadFile(file)
				if err != nil {
					return err
				}
				v.Egresses = append(v.Egresses, cloudinit.Egress{Name: name, Config: string(text), Resolve: config.ResolveFamily(res)})
			}
			if askPassword {
				pw, err := readPassword(false)
				if err != nil {
					return err
				}
				if v.AdminPasswordHash, err = auth.HashPassword(pw); err != nil {
					return err
				}
			}
			out, err := cloudinit.Render(v)
			if err != nil {
				return err
			}
			fmt.Print(out)
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&v.Repo, "repo", cloudinit.DefaultRepo, "GitHub repository with releases")
	f.StringVar(&v.Version, "version", "latest", "vwitch version to install")
	f.StringVar(&v.Endpoint, "endpoint", "", "public host clients connect to (default: auto-detect)")
	f.Uint16Var(&v.ListenPort, "listen-port", 0, "AmneziaWG UDP port")
	f.StringVar(&address, "address", "", "server address and client network")
	f.StringVar(&resolver, "resolver", "", "public DNS resolver for clients")
	f.BoolVar(&v.AllowDirect, "allow-direct", false, "allow the server's own uplink as egress (direct)")
	f.BoolVar(&v.LockdownSSH, "lockdown-ssh", false, "SSH only via NetBird once connected")
	f.StringVar(&v.Language, "language", "", "default UI language")
	f.StringVar(&v.NetBirdSetupKey, "netbird-setup-key", "", "install NetBird and join with this key")
	f.StringVar(&v.NetBirdManagementURL, "netbird-management-url", "", "self-hosted NetBird management URL")
	f.BoolVar(&askPassword, "ask-admin-password", false, "ask for the admin password and put only its bcrypt hash into the user data")
	f.StringArrayVar(&egresses, "egress", nil, "egress to import on first boot: name=file[:ipv6] (repeatable)")
	return cmd
}
