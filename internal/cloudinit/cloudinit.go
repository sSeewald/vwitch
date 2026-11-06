// Package cloudinit renders the cloud-init user data that installs vwitch.
package cloudinit

import (
	"bytes"
	"fmt"
	"net/netip"
	"strings"
	"text/template"

	"github.com/sseewald/vwitch/deploy"
	"github.com/sseewald/vwitch/internal/config"
	"github.com/sseewald/vwitch/internal/egress"

	"github.com/sseewald/vwitch/internal/version"
)

// DefaultRepo is the GitHub repository releases are downloaded from.
const DefaultRepo = version.Repo

// Egress is an exit imported on first boot.
type Egress struct {
	Name    string
	Config  string
	Resolve config.ResolveFamily
}

// Vars are the template inputs.
type Vars struct {
	Repo                 string
	Version              string // "latest" or X.Y.Z
	Endpoint             string
	ListenPort           uint16
	Address              netip.Prefix
	Resolver             netip.Addr
	AllowDirect          bool
	LockdownSSH          bool
	Language             string
	AdminPasswordHash    string // bcrypt; empty: generate a password on the server
	NetBirdSetupKey      string
	NetBirdManagementURL string
	Egresses             []Egress
}

// InstallArgs renders the install.sh options.
func (v Vars) InstallArgs() string {
	var args []string
	if v.Version != "latest" {
		args = append(args, "--version", v.Version)
	}
	if v.AdminPasswordHash == "" {
		args = append(args, "--password-file", "/root/vwitch-admin-password")
	}
	add := func(flag, val string) {
		if val != "" {
			args = append(args, flag, shellQuote(val))
		}
	}
	add("--admin-password-hash", v.AdminPasswordHash)
	add("--endpoint", v.Endpoint)
	if v.ListenPort != 0 {
		add("--listen-port", fmt.Sprint(v.ListenPort))
	}
	if v.Address.IsValid() {
		add("--address", v.Address.String())
	}
	if v.Resolver.IsValid() {
		add("--resolver", v.Resolver.String())
	}
	add("--language", v.Language)
	if v.AllowDirect {
		args = append(args, "--allow-direct")
	}
	if v.NetBirdSetupKey != "" {
		args = append(args, "--admin-interfaces", "lo,"+config.DefaultInterface+",wt0")
		if v.LockdownSSH {
			args = append(args, "--lockdown-ssh")
		}
	}
	return strings.Join(args, " ")
}

// Render validates the inputs and returns the user data.
func Render(v Vars) (string, error) {
	if v.Repo == "" {
		v.Repo = DefaultRepo
	}
	if v.Version == "" {
		v.Version = "latest"
	}
	v.Version = strings.TrimPrefix(v.Version, "v")
	if v.LockdownSSH && v.NetBirdSetupKey == "" {
		return "", fmt.Errorf("--lockdown-ssh needs NetBird, otherwise SSH would only be reachable locally")
	}
	for _, e := range v.Egresses {
		if _, err := egress.Import(e.Name, e.Config); err != nil {
			return "", fmt.Errorf("egress %s: %w", e.Name, err)
		}
	}
	t, err := template.New("cloud-init").Funcs(template.FuncMap{
		"indent": func(n int, s string) string {
			pad := strings.Repeat(" ", n)
			return pad + strings.ReplaceAll(strings.TrimRight(s, "\n"), "\n", "\n"+pad)
		},
	}).Parse(deploy.CloudInit)
	if err != nil {
		return "", err
	}
	var b bytes.Buffer
	if err := t.Execute(&b, v); err != nil {
		return "", err
	}
	return b.String(), nil
}

func shellQuote(s string) string {
	if strings.IndexFunc(s, func(r rune) bool {
		return (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && !strings.ContainsRune(".:-_/,", r)
	}) < 0 {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
