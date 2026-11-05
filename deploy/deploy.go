// Package deploy embeds the installation assets so "vwitch cloud-init" and
// the release packaging use the very same files.
package deploy

import _ "embed"

// CloudInit is the cloud-init template rendered by "vwitch cloud-init".
//
//go:embed cloud-init.yaml.tmpl
var CloudInit string
