//go:build linux

package health

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"

	"github.com/sseewald/vwitch/internal/config"
	"github.com/sseewald/vwitch/internal/sockopt"
)

// Probe runs one target through the given interface. Routing rule
// "oif <iface> lookup <table>" makes the bound socket use the tunnel.
func Probe(ctx context.Context, iface string, t config.Target, timeout time.Duration) (time.Duration, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	start := time.Now()
	var err error
	if t.Ping != "" {
		err = ping(ctx, iface, t.Ping)
	} else {
		err = httpGet(ctx, iface, t.URL)
	}
	return time.Since(start), err
}

func httpGet(ctx context.Context, iface, url string) error {
	d := &net.Dialer{Control: sockopt.BindToDevice(iface)}
	tr := &http.Transport{DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
		return d.DialContext(ctx, "tcp4", addr)
	}, DisableKeepAlives: true}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("http status %d", resp.StatusCode)
	}
	return nil
}

func ping(ctx context.Context, iface, host string) error {
	dst := net.ParseIP(host).To4()
	if dst == nil {
		return errors.New("ping target must be IPv4")
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_ICMP)
	if err != nil {
		return err
	}
	if err := unix.SetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, iface); err != nil {
		_ = unix.Close(fd)
		return err
	}
	f := os.NewFile(uintptr(fd), "icmp")
	pc, err := net.FilePacketConn(f)
	_ = f.Close()
	if err != nil {
		return err
	}
	defer func() { _ = pc.Close() }()
	if dl, ok := ctx.Deadline(); ok {
		_ = pc.SetDeadline(dl)
	}
	id := os.Getpid() & 0xffff
	msg := icmp.Message{Type: ipv4.ICMPTypeEcho, Body: &icmp.Echo{ID: id, Seq: 1, Data: []byte("vwitch")}}
	b, err := msg.Marshal(nil)
	if err != nil {
		return err
	}
	if _, err := pc.WriteTo(b, &net.IPAddr{IP: dst}); err != nil {
		return err
	}
	buf := make([]byte, 1500)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			return err
		}
		ip, ok := from.(*net.IPAddr)
		if !ok || !ip.IP.Equal(dst) || n < 8 {
			continue
		}
		// Go's IPConn usually strips the IPv4 header; strip it if present
		msg := buf[:n]
		if msg[0]>>4 == 4 {
			msg = msg[int(msg[0]&0x0f)*4:]
		}
		rm, err := icmp.ParseMessage(1, msg)
		if err != nil {
			continue
		}
		if echo, ok := rm.Body.(*icmp.Echo); ok && rm.Type == ipv4.ICMPTypeEchoReply && echo.ID == id {
			return nil
		}
	}
}
