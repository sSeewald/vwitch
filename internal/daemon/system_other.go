//go:build !linux

package daemon

import (
	"errors"
	"log/slog"
)

// NewSystem is only available on Linux.
func NewSystem(*slog.Logger) (System, error) {
	return nil, errors.New("vwitch serve runs on Linux only")
}
