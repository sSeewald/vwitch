package dns

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/sseewald/vwitch/internal/sockopt"
)

// Route tells the forwarder how a client's queries leave the server:
// through iface ("" = server uplink), or not at all (ok == false).
type Route func(client netip.Addr) (iface string, ok bool)

// Forwarder answers the local UI names itself and forwards everything else
// to the public resolver through the asking client's current exit.
type Forwarder struct {
	Listen   netip.Addr
	Upstream netip.AddrPort
	Names    func() []string // local names, e.g. vwitch.internal
	Route    Route
	Timeout  time.Duration
	Log      *slog.Logger
}

// Serve listens on UDP and TCP port 53 until ctx ends.
func (f *Forwarder) Serve(ctx context.Context) error {
	addr := netip.AddrPortFrom(f.Listen, 53)
	uc, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(addr))
	if err != nil {
		return err
	}
	tl, err := net.ListenTCP("tcp4", net.TCPAddrFromAddrPort(addr))
	if err != nil {
		_ = uc.Close()
		return err
	}
	go func() {
		<-ctx.Done()
		_ = uc.Close()
		_ = tl.Close()
	}()
	go f.serveTCP(ctx, tl)
	buf := make([]byte, 65535)
	for {
		n, from, err := uc.ReadFromUDPAddrPort(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		q := append([]byte(nil), buf[:n]...)
		go func() {
			if resp := f.handle(ctx, q, from.Addr(), "udp"); resp != nil {
				if _, err := uc.WriteToUDPAddrPort(resp, from); err != nil {
					f.Log.Warn("dns reply failed", "client", from, "err", err)
				}
			}
		}()
	}
}

func (f *Forwarder) serveTCP(ctx context.Context, l *net.TCPListener) {
	for {
		c, err := l.AcceptTCP()
		if err != nil {
			return
		}
		go func() {
			defer func() { _ = c.Close() }()
			_ = c.SetDeadline(time.Now().Add(10 * time.Second))
			q, err := readTCPMsg(c)
			if err != nil {
				return
			}
			from := c.RemoteAddr().(*net.TCPAddr).AddrPort().Addr()
			if resp := f.handle(ctx, q, from, "tcp"); resp != nil {
				_ = writeTCPMsg(c, resp)
			}
		}()
	}
}

func (f *Forwarder) handle(ctx context.Context, q []byte, client netip.Addr, network string) []byte {
	f.Log.Debug("dns query", "client", client, "net", network, "len", len(q))
	var p dnsmessage.Parser
	h, err := p.Start(q)
	if err != nil {
		return nil
	}
	question, err := p.Question()
	if err != nil {
		return nil
	}
	if f.isLocal(question.Name.String()) {
		return f.localAnswer(h, question)
	}
	iface, ok := f.Route(client.Unmap())
	if !ok {
		return reply(h, question, dnsmessage.RCodeRefused, nil)
	}
	resp, err := f.exchange(ctx, q, iface, network)
	if err != nil {
		f.Log.Debug("dns forward failed", "client", client, "err", err)
		return reply(h, question, dnsmessage.RCodeServerFailure, nil)
	}
	return resp
}

func (f *Forwarder) isLocal(name string) bool {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	for _, n := range f.Names() {
		if strings.EqualFold(strings.TrimSuffix(n, "."), name) {
			return true
		}
	}
	return false
}

func (f *Forwarder) localAnswer(h dnsmessage.Header, q dnsmessage.Question) []byte {
	if q.Type != dnsmessage.TypeA {
		return reply(h, q, dnsmessage.RCodeSuccess, nil) // NODATA, e.g. for AAAA
	}
	a := f.Listen.As4()
	return reply(h, q, dnsmessage.RCodeSuccess, &dnsmessage.AResource{A: a})
}

func reply(h dnsmessage.Header, q dnsmessage.Question, rc dnsmessage.RCode, a *dnsmessage.AResource) []byte {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, Response: true, Authoritative: a != nil,
		RecursionDesired: h.RecursionDesired, RecursionAvailable: true, RCode: rc})
	b.EnableCompression()
	_ = b.StartQuestions()
	_ = b.Question(q)
	if a != nil {
		_ = b.StartAnswers()
		_ = b.AResource(dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: 60}, *a)
	}
	out, err := b.Finish()
	if err != nil {
		return nil
	}
	return out
}

func (f *Forwarder) exchange(ctx context.Context, q []byte, iface, network string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, f.Timeout)
	defer cancel()
	d := &net.Dialer{Control: sockopt.BindToDevice(iface)}
	c, err := d.DialContext(ctx, network+"4", f.Upstream.String())
	if err != nil {
		return nil, err
	}
	defer func() { _ = c.Close() }()
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	}
	if network == "tcp" {
		if err := writeTCPMsg(c, q); err != nil {
			return nil, err
		}
		return readTCPMsg(c)
	}
	if _, err := c.Write(q); err != nil {
		return nil, err
	}
	buf := make([]byte, 65535)
	n, err := c.Read(buf)
	if err != nil {
		return nil, err
	}
	if n < 2 || binary.BigEndian.Uint16(buf) != binary.BigEndian.Uint16(q) {
		return nil, errors.New("mismatched dns reply")
	}
	return buf[:n], nil
}

func readTCPMsg(r io.Reader) ([]byte, error) {
	var l [2]byte
	if _, err := io.ReadFull(r, l[:]); err != nil {
		return nil, err
	}
	msg := make([]byte, binary.BigEndian.Uint16(l[:]))
	_, err := io.ReadFull(r, msg)
	return msg, err
}

func writeTCPMsg(w io.Writer, msg []byte) error {
	out := binary.BigEndian.AppendUint16(nil, uint16(len(msg)))
	_, err := w.Write(append(out, msg...))
	return err
}
