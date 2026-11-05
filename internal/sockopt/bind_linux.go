//go:build linux

// Package sockopt binds sockets to an interface so traffic from the server
// itself (probes, DNS forwarding) can leave through a chosen egress.
package sockopt

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// BindToDevice returns a net.Dialer Control func; empty iface means unbound.
func BindToDevice(iface string) func(network, address string, c syscall.RawConn) error {
	if iface == "" {
		return nil
	}
	return func(_, _ string, c syscall.RawConn) error {
		var serr error
		if err := c.Control(func(fd uintptr) {
			serr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, iface)
		}); err != nil {
			return err
		}
		return serr
	}
}
