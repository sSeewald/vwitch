// Package version is the single source of the vwitch version. Releases set
// it at link time:
//
//	-ldflags "-X github.com/sseewald/vwitch/internal/version.version=1.2.3"
//
// Other builds fall back to the Go build info (module version for
// 'go install', otherwise the VCS revision), and finally to "dev".
package version

import (
	"runtime/debug"
	"strings"
)

var version string

// Repo is the GitHub repository (owner/name): source, releases, docs.
const Repo = "sseewald/vwitch"

// RepoURL is the repository's web address.
const RepoURL = "https://github.com/" + Repo

// String returns the version without a leading "v", e.g. "1.2.3",
// "dev-3f2a9c1" or "dev".
func String() string {
	if version != "" {
		return strings.TrimPrefix(version, "v")
	}
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return "dev"
	}
	return fromBuildInfo(bi)
}

func fromBuildInfo(bi *debug.BuildInfo) string {
	if v := bi.Main.Version; v != "" && v != "(devel)" {
		return strings.TrimPrefix(v, "v")
	}
	var rev string
	var dirty bool
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			dirty = s.Value == "true"
		}
	}
	if rev == "" {
		return "dev"
	}
	out := "dev-" + rev[:min(7, len(rev))]
	if dirty {
		out += "-dirty"
	}
	return out
}
