package main

import (
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/sseewald/vwitch/internal/config"
	"github.com/sseewald/vwitch/internal/setup"
)

// initFromEnv creates the configuration on first start of a container.
// Variables: VWITCH_ENDPOINT (required unless auto-detection is fine),
// VWITCH_LISTEN_PORT, VWITCH_ADDRESS, VWITCH_RESOLVER, VWITCH_ALLOW_DIRECT,
// VWITCH_ADMIN_INTERFACES, VWITCH_LANGUAGE, VWITCH_ADMIN_USER, VWITCH_ADMIN_PASSWORD.
// The generated password is written next to the config.
func initFromEnv(path string, log *slog.Logger) error {
	if _, err := os.Stat(path); err == nil {
		return nil
	}
	env := func(k string) string { return strings.TrimSpace(os.Getenv("VWITCH_" + k)) }
	o := setup.Options{Endpoint: env("ENDPOINT"), Language: env("LANGUAGE"), Username: env("ADMIN_USER"), Password: env("ADMIN_PASSWORD")}
	var err error
	if o.Endpoint == "" {
		ip, err := setup.DetectEndpoint()
		if err != nil {
			return fmt.Errorf("set VWITCH_ENDPOINT: %w", err)
		}
		o.Endpoint = ip.String()
	}
	if v := env("LISTEN_PORT"); v != "" {
		p, err := strconv.ParseUint(v, 10, 16)
		if err != nil {
			return fmt.Errorf("VWITCH_LISTEN_PORT: %w", err)
		}
		o.ListenPort = uint16(p)
	}
	if v := env("ADDRESS"); v != "" {
		if o.Address, err = netip.ParsePrefix(v); err != nil {
			return fmt.Errorf("VWITCH_ADDRESS: %w", err)
		}
	}
	if v := env("RESOLVER"); v != "" {
		if o.Resolver, err = netip.ParseAddr(v); err != nil {
			return fmt.Errorf("VWITCH_RESOLVER: %w", err)
		}
	}
	o.AllowDirect, _ = strconv.ParseBool(env("ALLOW_DIRECT"))
	if v := env("ADMIN_INTERFACES"); v != "" {
		o.AdminInterfaces = strings.Split(v, ",")
	}
	c, pw, err := setup.NewConfig(o)
	if err != nil {
		return err
	}
	if _, err := config.Create(path, c); err != nil {
		return err
	}
	pwFile := filepath.Join(filepath.Dir(path), "admin-password")
	if err := os.WriteFile(pwFile, []byte(pw+"\n"), 0o600); err != nil {
		return err
	}
	log.Info("created configuration", "path", path, "endpoint", c.Server.Endpoint, "admin_user", c.Web.Admin.Username, "admin_password_file", pwFile)
	return nil
}
