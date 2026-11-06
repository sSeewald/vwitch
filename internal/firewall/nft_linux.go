//go:build linux

package firewall

import (
	"fmt"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// Apply replaces vwitch's tables atomically in one netlink batch. Other
// tables are never touched.
func Apply(rules []Rule) error {
	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("nftables: %w", err)
	}
	filter := &nftables.Table{Family: nftables.TableFamilyINet, Name: TableFilter}
	nat := &nftables.Table{Family: nftables.TableFamilyIPv4, Name: TableNAT}
	for _, t := range []*nftables.Table{filter, nat} {
		// add+delete+add: delete never fails and the swap is atomic
		conn.AddTable(t)
		conn.DelTable(t)
		conn.AddTable(t)
	}
	accept := nftables.ChainPolicyAccept
	chains := map[Chain]*nftables.Chain{
		ChainInput: conn.AddChain(&nftables.Chain{Name: string(ChainInput), Table: filter,
			Type: nftables.ChainTypeFilter, Hooknum: nftables.ChainHookInput, Priority: nftables.ChainPriorityFilter, Policy: &accept}),
		ChainForward: conn.AddChain(&nftables.Chain{Name: string(ChainForward), Table: filter,
			Type: nftables.ChainTypeFilter, Hooknum: nftables.ChainHookForward, Priority: nftables.ChainPriorityFilter, Policy: &accept}),
		ChainPrerouting: conn.AddChain(&nftables.Chain{Name: string(ChainPrerouting), Table: nat,
			Type: nftables.ChainTypeNAT, Hooknum: nftables.ChainHookPrerouting, Priority: nftables.ChainPriorityNATDest, Policy: &accept}),
		ChainPostrouting: conn.AddChain(&nftables.Chain{Name: string(ChainPostrouting), Table: nat,
			Type: nftables.ChainTypeNAT, Hooknum: nftables.ChainHookPostrouting, Priority: nftables.ChainPriorityNATSource, Policy: &accept}),
	}
	for _, r := range rules {
		c := chains[r.Chain]
		exprs, err := Exprs(r, c.Table.Family == nftables.TableFamilyINet)
		if err != nil {
			return fmt.Errorf("rule %q: %w", r, err)
		}
		conn.AddRule(&nftables.Rule{Table: c.Table, Chain: c, Exprs: exprs})
	}
	if err := conn.Flush(); err != nil {
		return fmt.Errorf("nftables flush: %w", err)
	}
	return nil
}

// Exprs compiles a rule to nftables expressions. inet is true for rules in
// the inet table, where IPv4 header matches need an nfproto guard.
func Exprs(r Rule, inet bool) ([]expr.Any, error) { return exprs(r, inet, nil) }

// exprs also resolves set references to the sets created in the same batch.
func exprs(r Rule, inet bool, sets map[string]*nftables.Set) ([]expr.Any, error) {
	var e []expr.Any
	cmp := func(op expr.CmpOp, data []byte) {
		e = append(e, &expr.Cmp{Op: op, Register: 1, Data: data})
	}
	meta := func(k expr.MetaKey) { e = append(e, &expr.Meta{Key: k, Register: 1}) }

	if r.IPv6 {
		meta(expr.MetaKeyNFPROTO)
		cmp(expr.CmpOpEq, []byte{unix.NFPROTO_IPV6})
	}
	if r.IIF != "" {
		meta(expr.MetaKeyIIFNAME)
		cmp(expr.CmpOpEq, ifname(r.IIF))
	}
	if r.OIF != "" {
		meta(expr.MetaKeyOIFNAME)
		cmp(expr.CmpOpEq, ifname(r.OIF))
	}
	for _, i := range r.OIFNot {
		meta(expr.MetaKeyOIFNAME)
		cmp(expr.CmpOpNeq, ifname(i))
	}
	for _, i := range r.IIFNot {
		meta(expr.MetaKeyIIFNAME)
		cmp(expr.CmpOpNeq, ifname(i))
	}
	if r.Saddr.IsValid() {
		if inet {
			meta(expr.MetaKeyNFPROTO)
			cmp(expr.CmpOpEq, []byte{unix.NFPROTO_IPV4})
		}
		e = append(e, &expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4})
		if !r.Saddr.IsSingleIP() {
			mask := make([]byte, 4)
			for i := 0; i < r.Saddr.Bits(); i++ {
				mask[i/8] |= 0x80 >> (i % 8)
			}
			e = append(e, &expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: mask, Xor: make([]byte, 4)})
		}
		a := r.Saddr.Masked().Addr().As4()
		cmp(expr.CmpOpEq, a[:])
	}
	if r.Daddr.IsValid() {
		if inet {
			meta(expr.MetaKeyNFPROTO)
			cmp(expr.CmpOpEq, []byte{unix.NFPROTO_IPV4})
		}
		e = append(e, &expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4})
		a := r.Daddr.As4()
		cmp(expr.CmpOpEq, a[:])
	}
	if r.CtEstablished {
		e = append(e,
			&expr.Ct{Register: 1, Key: expr.CtKeySTATE},
			&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4,
				Mask: binaryutil.NativeEndian.PutUint32(expr.CtStateBitESTABLISHED | expr.CtStateBitRELATED),
				Xor:  make([]byte, 4)})
		cmp(expr.CmpOpNeq, make([]byte, 4))
	}
	if r.CtNew {
		e = append(e,
			&expr.Ct{Register: 1, Key: expr.CtKeySTATE},
			&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4,
				Mask: binaryutil.NativeEndian.PutUint32(expr.CtStateBitNEW), Xor: make([]byte, 4)})
		cmp(expr.CmpOpNeq, make([]byte, 4))
	}
	if s := r.Set; s != nil {
		proto, off, n := byte(unix.NFPROTO_IPV4), uint32(12), uint32(4)
		if s.IPv6 {
			proto, off, n = unix.NFPROTO_IPV6, 8, 16
		}
		if s.Dst {
			off += n
		}
		if inet {
			meta(expr.MetaKeyNFPROTO)
			cmp(expr.CmpOpEq, []byte{proto})
		}
		e = append(e, &expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: off, Len: n})
		l := &expr.Lookup{SourceRegister: 1, SetName: s.Set, Invert: s.Invert}
		if set, ok := sets[s.Set]; ok {
			l.SetID = set.ID
		}
		e = append(e, l)
	}
	if r.Proto != 0 {
		meta(expr.MetaKeyL4PROTO)
		cmp(expr.CmpOpEq, []byte{r.Proto})
	}
	if r.DPort != 0 {
		e = append(e, &expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2})
		cmp(expr.CmpOpEq, binaryutil.BigEndian.PutUint16(r.DPort))
	}

	switch r.Verdict {
	case Accept:
		e = append(e, &expr.Verdict{Kind: expr.VerdictAccept})
	case Drop:
		e = append(e, &expr.Verdict{Kind: expr.VerdictDrop})
	case Masquerade:
		e = append(e, &expr.Masq{})
	case Reject:
		if !inet {
			return nil, fmt.Errorf("reject is only used in inet tables")
		}
		e = append(e, &expr.Reject{Type: unix.NFT_REJECT_ICMPX_UNREACH, Code: unix.NFT_REJECT_ICMPX_ADMIN_PROHIBITED})
	case Log:
		e = append(e,
			&expr.Limit{Type: expr.LimitTypePkts, Rate: logRate, Unit: expr.LimitTimeSecond, Burst: logRate},
			&expr.Log{Key: 1<<unix.NFTA_LOG_GROUP | 1<<unix.NFTA_LOG_PREFIX, Group: LogGroup, Data: []byte(r.LogPrefix)})
	case DNAT:
		if !r.NATAddr.Is4() {
			return nil, fmt.Errorf("dnat needs an IPv4 address")
		}
		a := r.NATAddr.As4()
		e = append(e, &expr.Immediate{Register: 1, Data: a[:]})
		nat := &expr.NAT{Type: expr.NATTypeDestNAT, Family: unix.NFPROTO_IPV4, RegAddrMin: 1}
		if r.NATPort != 0 {
			// "Specified" means a port range is given; without a port it
			// would rewrite the destination port to 0
			e = append(e, &expr.Immediate{Register: 2, Data: binaryutil.BigEndian.PutUint16(r.NATPort)})
			nat.RegProtoMin, nat.Specified = 2, true
		}
		e = append(e, nat)
	default:
		return nil, fmt.Errorf("unknown verdict %q", r.Verdict)
	}
	return e, nil
}

func ifname(n string) []byte {
	b := make([]byte, unix.IFNAMSIZ)
	copy(b, n)
	return b
}
