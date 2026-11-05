package version

import (
	"runtime/debug"
	"testing"
)

func TestFromBuildInfo(t *testing.T) {
	for _, tc := range []struct {
		bi   debug.BuildInfo
		want string
	}{
		{debug.BuildInfo{Main: debug.Module{Version: "v1.4.0"}}, "1.4.0"},
		{debug.BuildInfo{Main: debug.Module{Version: "(devel)"}}, "dev"},
		{debug.BuildInfo{Main: debug.Module{Version: "(devel)"}, Settings: []debug.BuildSetting{
			{Key: "vcs.revision", Value: "3f2a9c1d0e"}, {Key: "vcs.modified", Value: "true"}}}, "dev-3f2a9c1-dirty"},
	} {
		if got := fromBuildInfo(&tc.bi); got != tc.want {
			t.Errorf("got %q, want %q", got, tc.want)
		}
	}
}
