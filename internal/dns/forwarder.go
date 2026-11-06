package dns

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/sseewald/vwitch/internal/sockopt"
)

// Route tells the forwarder how a client's query for name leaves the server:
// through iface ("" = server uplink), or not at all (ok == false).
type Route func(client netip.Addr, name string) (iface string, ok bool)

// Learn receives the IPv4 addresses of an answer before the client gets it,
// so routing can follow the name (domain routes). ttl is the lowest TTL.
type Learn func(name string, addrs []netip.Addr, ttl time.Duration)

// Block reports whether name is blocked for client, and by which source.
type Block func(client netip.Addr, name string) (source string, ok bool)

// Seen records an IPv4 lookup (activity list, block log); source is the
// blocking source or empty when the lookup was answered normally.
type Seen func(client netip.Addr, name, source string)

// Forwarder answers the local UI names itself and forwards everything else
// to the public resolver through the asking client's current exit, caching
// answers per egress.
type Forwarder struct {
	Listen   netip.Addr
	Upstream netip.AddrPort
	Names    func() []string // local names, e.g. vwitch.internal
	// Protect is the client network. Upstream answers pointing into it are
	// dropped, so a foreign name cannot be rebound to the server or a client.
	// Other private ranges stay allowed: names may resolve into an egress LAN.
	Protect netip.Prefix
	Route   Route
	Learn   Learn // optional
	Block   Block // optional
	Seen    Seen  // optional
	Timeout time.Duration
	Log     *slog.Logger

	once  sync.Once
	cache *cache
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
	name := strings.TrimSuffix(strings.ToLower(question.Name.String()), ".")
	client = client.Unmap()
	source, blocked := "", false
	if f.Block != nil {
		if source, blocked = f.Block(client, name); !blocked {
			source = ""
		}
	}
	if f.Seen != nil && question.Type == dnsmessage.TypeA {
		f.Seen(client, name, source)
	}
	if blocked {
		return blockedAnswer(h, question)
	}
	iface, ok := f.Route(client, name)
	if !ok {
		return reply(h, question, dnsmessage.RCodeRefused, nil)
	}
	f.once.Do(func() { f.cache = newCache() })
	k := cacheKeyOf(question, iface)
	resp := f.cache.get(k, h.ID)
	if resp != nil && network == "udp" && len(resp) > udpLimit(q) {
		resp = nil // too big for this client's UDP buffer: ask upstream, it truncates
	}
	if resp == nil {
		var err error
		if resp, err = f.exchange(ctx, q, iface, network); err != nil {
			f.Log.Debug("dns forward failed", "client", client, "err", err)
			return reply(h, question, dnsmessage.RCodeServerFailure, nil)
		}
		f.cache.put(k, resp)
	}
	addrs, ttl := answerAddrs(resp)
	if f.Protect.IsValid() && slices.ContainsFunc(addrs, f.Protect.Contains) {
		f.Log.Info("dns answer into the client network dropped", "client", client, "name", name)
		return reply(h, question, dnsmessage.RCodeSuccess, nil)
	}
	// also on cache hits, so domain routes keep their addresses
	if f.Learn != nil && question.Type == dnsmessage.TypeA && len(addrs) > 0 {
		f.Learn(name, addrs, ttl)
	}
	return resp
}

// answerAddrs returns the A records of a response and their lowest TTL.
func answerAddrs(resp []byte) ([]netip.Addr, time.Duration) {
	var p dnsmessage.Parser
	if _, err := p.Start(resp); err != nil {
		return nil, 0
	}
	if err := p.SkipAllQuestions(); err != nil {
		return nil, 0
	}
	var addrs []netip.Addr
	ttl := uint32(0)
	for {
		h, err := p.AnswerHeader()
		if err != nil {
			break
		}
		if h.Type != dnsmessage.TypeA {
			if err := p.SkipAnswer(); err != nil {
				break
			}
			continue
		}
		a, err := p.AResource()
		if err != nil {
			break
		}
		addrs = append(addrs, netip.AddrFrom4(a.A))
		if ttl == 0 || h.TTL < ttl {
			ttl = h.TTL
		}
	}
	return addrs, time.Duration(ttl) * time.Second
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

// blockedAnswer answers A with 0.0.0.0 and every other type without data:
// the client gives up at once instead of retrying like after NXDOMAIN.
func blockedAnswer(h dnsmessage.Header, q dnsmessage.Question) []byte {
	if q.Type != dnsmessage.TypeA {
		return reply(h, q, dnsmessage.RCodeSuccess, nil)
	}
	return reply(h, q, dnsmessage.RCodeSuccess, &dnsmessage.AResource{})
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
