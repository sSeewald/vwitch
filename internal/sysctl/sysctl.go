// Package sysctl sets the kernel parameters vwitch depends on.
package sysctl

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Required are the settings for forwarding client traffic. IPv6 forwarding
// is left alone (the firewall drops IPv6 from clients) so the host's own
// IPv6 setup is not affected.
var Required = map[string]string{
	"net.ipv4.ip_forward":             "1",
	"net.ipv4.conf.all.rp_filter":     "2",
	"net.ipv4.conf.default.rp_filter": "2",
}

// Apply writes settings below root (normally /proc/sys) that differ from the
// wanted value. Values that are already correct are not written, so a
// container with read-only /proc/sys works when the host set them.
func Apply(root string, settings map[string]string) error {
	var errs []error
	for k, v := range settings {
		p := filepath.Join(root, strings.ReplaceAll(k, ".", "/"))
		if cur, err := os.ReadFile(p); err == nil && strings.TrimSpace(string(cur)) == v {
			continue
		}
		if err := os.WriteFile(p, []byte(v), 0o644); err != nil {
			errs = append(errs, fmt.Errorf("sysctl %s=%s (set it on the host): %w", k, v, err))
		}
	}
	return errors.Join(errs...)
}
