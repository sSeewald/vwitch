//go:build linux

package nflog

import (
	"context"

	gonflog "github.com/florianl/go-nflog/v2"
)

// Listen delivers the packets logged to group until ctx ends.
func Listen(ctx context.Context, group uint16, fn func(Hit)) error {
	nf, err := gonflog.Open(&gonflog.Config{Group: group, Copymode: gonflog.CopyPacket, Bufsize: 128})
	if err != nil {
		return err
	}
	defer func() { _ = nf.Close() }()
	err = nf.RegisterWithErrorFunc(ctx, func(a gonflog.Attribute) int {
		if a.Payload == nil {
			return 0
		}
		prefix := ""
		if a.Prefix != nil {
			prefix = *a.Prefix
		}
		if h, ok := Decode(prefix, *a.Payload); ok {
			fn(h)
		}
		return 0
	}, func(error) int { return 0 }) // keep listening on transient errors
	if err != nil {
		return err
	}
	<-ctx.Done()
	return nil
}
