//go:build linux

package exposure

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Listening reads all listening sockets from /proc and names their process.
func Listening() ([]Socket, error) {
	var all []Socket
	for _, f := range []struct{ file, proto string }{
		{"tcp", "tcp"}, {"tcp6", "tcp"}, {"udp", "udp"}, {"udp6", "udp"},
	} {
		fh, err := os.Open(filepath.Join("/proc/net", f.file))
		if err != nil {
			continue // e.g. IPv6 disabled
		}
		s, err := ParseProcNet(fh, f.proto)
		_ = fh.Close()
		if err != nil {
			return nil, err
		}
		all = append(all, s...)
	}
	names := processes()
	for i := range all {
		all[i].Process = names[all[i].Inode]
	}
	return all, nil
}

// processes maps socket inodes to process names (best effort).
func processes() map[uint64]string {
	out := map[uint64]string{}
	pids, _ := os.ReadDir("/proc")
	for _, p := range pids {
		if _, err := strconv.Atoi(p.Name()); err != nil {
			continue
		}
		comm, err := os.ReadFile(filepath.Join("/proc", p.Name(), "comm"))
		if err != nil {
			continue
		}
		fds, _ := os.ReadDir(filepath.Join("/proc", p.Name(), "fd"))
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join("/proc", p.Name(), "fd", fd.Name()))
			if err != nil {
				continue
			}
			if rest, ok := strings.CutPrefix(link, "socket:["); ok {
				if inode, err := strconv.ParseUint(strings.TrimSuffix(rest, "]"), 10, 64); err == nil {
					out[inode] = strings.TrimSpace(string(comm))
				}
			}
		}
	}
	return out
}
