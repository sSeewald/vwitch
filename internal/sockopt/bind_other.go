//go:build !linux

package sockopt

import "syscall"

// BindToDevice is a no-op outside Linux (used only by tests there).
func BindToDevice(string) func(network, address string, c syscall.RawConn) error { return nil }
