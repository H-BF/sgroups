package nft

import (
	"fmt"
	"net"

	model "github.com/H-BF/sgroups/internal/models/sgroups"

	di "github.com/H-BF/corlib/pkg/dict"
	"github.com/c-robinson/iplib"
	nftLib "github.com/google/nftables"
	. "github.com/google/nftables/binaryutil"
	. "github.com/google/nftables/expr"
	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

func beginRule() ruleBuilder {
	return ruleBuilder{}
}

type ruleBuilder struct {
	sets  di.HDict[uint32, NfSet]
	exprs []Any
}

func (rb ruleBuilder) applyRule(chn *nftLib.Chain, c *nftLib.Conn) {
	if len(rb.exprs) > 0 {
		rb.sets.Iterate(func(id uint32, s NfSet) bool {
			s.Table = chn.Table
			if e := c.AddSet(s.Set, s.Elements); e != nil {
				panic(e)
			}
			return true
		})
		_ = c.AddRule(&nftLib.Rule{
			Table: chn.Table,
			Chain: chn,
			Exprs: rb.exprs,
		})
	}
}

func (rb ruleBuilder) dlogs(f LogFlags) ruleBuilder { //nolint:unparam
	rb.exprs = append(rb.exprs,
		&Log{
			Flags: f,
			Level: LogLevelDebug,
			Key: (1<<unix.NFTA_LOG_FLAGS)*tern(f == 0, uint32(0), 1) |
				(1 << unix.NFTA_LOG_LEVEL),
		})
	return rb
}

func (rb ruleBuilder) nop() ruleBuilder { //nolint:unused
	return rb
}

func (rb ruleBuilder) accept() ruleBuilder {
	rb.exprs = append(rb.exprs,
		&Verdict{Kind: VerdictAccept},
	)
	return rb
}

func (rb ruleBuilder) drop() ruleBuilder {
	rb.exprs = append(rb.exprs,
		&Verdict{Kind: VerdictDrop},
	)
	return rb
}

func (rb ruleBuilder) ruleAction2Verdict(a model.RuleAction) ruleBuilder {
	var f func() ruleBuilder
	switch a {
	case model.RA_ACCEPT:
		f = rb.accept
	case model.RA_DROP:
		f = rb.drop
	}
	return f()
}

func (rb ruleBuilder) jump(chain string) ruleBuilder { //nolint:unused
	rb.exprs = append(rb.exprs,
		&Verdict{Kind: VerdictJump, Chain: chain},
	)
	return rb
}

func (rb ruleBuilder) go2(chain string) ruleBuilder {
	rb.exprs = append(rb.exprs,
		&Verdict{Kind: VerdictGoto, Chain: chain},
	)
	return rb
}

func (rb ruleBuilder) counter() ruleBuilder {
	rb.exprs = append(rb.exprs, &Counter{})
	return rb
}

func (rb ruleBuilder) inSet(s *nftLib.Set) ruleBuilder {
	if s != nil {
		n := s.Name
		if s.Anonymous {
			n = fmt.Sprintf(s.Name, s.ID)
		}
		rb.exprs = append(rb.exprs,
			&Lookup{
				SourceRegister: 1,
				SetName:        n,
				SetID:          s.ID,
			})
	}
	return rb
}

func (rb ruleBuilder) saddr(ipVer int) ruleBuilder {
	switch ipVer {
	case iplib.IP4Version:
		return rb.saddr4()
	case iplib.IP6Version:
		return rb.saddr6()
	default:
		panic(fmt.Errorf("unsuppoeted proto ver '%v'", ipVer))
	}
}

func (rb ruleBuilder) daddr(ipVer int) ruleBuilder {
	switch ipVer {
	case iplib.IP4Version:
		return rb.daddr4()
	case iplib.IP6Version:
		return rb.daddr6()
	default:
		panic(fmt.Errorf("unsuppoeted proto ver '%v'", ipVer))
	}
}

func (rb ruleBuilder) saddr6() ruleBuilder {
	rb.exprs = append(rb.ip6().exprs,
		&Payload{
			DestRegister: 1,
			Base:         PayloadBaseNetworkHeader,
			Offset:       uint32(8),  //nolint:mnd
			Len:          uint32(16), //nolint:mnd
		},
	)
	return rb
}

func (rb ruleBuilder) daddr6() ruleBuilder {
	rb.exprs = append(rb.ip6().exprs,
		&Payload{
			DestRegister: 1,
			Base:         PayloadBaseNetworkHeader,
			Offset:       uint32(24), //nolint:mnd
			Len:          uint32(16), //nolint:mnd
		},
	)
	return rb
}

func (rb ruleBuilder) saddr4() ruleBuilder {
	rb.exprs = append(rb.ip4().exprs, //ip
		&Payload{
			DestRegister: 1,
			Base:         PayloadBaseNetworkHeader,
			Offset:       uint32(12), //nolint:mnd
			Len:          uint32(4),  //nolint:mnd
		}, //saddr
	)
	return rb
}

func (rb ruleBuilder) daddr4() ruleBuilder {
	rb.exprs = append(rb.ip4().exprs, //ip
		&Payload{
			DestRegister: 1,
			Base:         PayloadBaseNetworkHeader,
			Offset:       uint32(16), //nolint:mnd
			Len:          uint32(4),  //nolint:mnd
		}, //daddr
	)
	return rb
}

func (rb ruleBuilder) sport() ruleBuilder {
	rb.exprs = append(rb.exprs,
		&Payload{
			DestRegister: 1,
			Base:         PayloadBaseTransportHeader,
			Offset:       0,
			Len:          2,
		},
	)
	return rb
}

func (rb ruleBuilder) dport() ruleBuilder {
	rb.exprs = append(rb.exprs,
		&Payload{
			DestRegister: 1,
			Base:         PayloadBaseTransportHeader,
			Offset:       2,
			Len:          2,
		},
	)
	return rb
}

func (rb ruleBuilder) metaL4PROTO() ruleBuilder {
	rb.exprs = append(rb.exprs,
		&Meta{Key: MetaKeyL4PROTO, Register: 1},
	)
	return rb
}

func (rb ruleBuilder) protoIP(tr model.NetworkTransport) ruleBuilder {
	var t byte
	switch tr {
	case model.TCP:
		t = unix.IPPROTO_TCP
	case model.UDP:
		t = unix.IPPROTO_UDP
	default:
		panic("UB")
	}
	rb.exprs = append(rb.metaL4PROTO().exprs,
		&Cmp{
			Op:       CmpOpEq,
			Register: 1,
			Data:     []byte{t},
		},
	)
	return rb
}

func (rb ruleBuilder) protoICMP(d model.ICMP) ruleBuilder {
	var proto byte
	switch d.IPv {
	case model.IPv4:
		proto = unix.IPPROTO_ICMP
	case model.IPv6:
		proto = unix.IPPROTO_ICMPV6
	default:
		panic(
			errors.Errorf("unsusable proto family(%v)", d.IPv),
		)
	}
	rb.exprs = append(rb.metaL4PROTO().exprs,
		&Cmp{
			Op:       CmpOpEq,
			Register: 1,
			Data:     []byte{proto},
		},
	)
	if n := d.Types.Len(); n > 0 {
		set := &nftLib.Set{
			ID:        nextSetID(),
			Name:      "__set%d",
			Anonymous: true,
			Constant:  true,
			KeyType: tern(d.IPv == model.IPv4,
				nftLib.TypeICMPType, nftLib.TypeICMP6Type),
		}
		elements := make([]nftLib.SetElement, 0, n)
		d.Types.Iterate(func(v uint8) bool {
			elements = append(elements,
				nftLib.SetElement{Key: []byte{v}},
			)
			return true
		})
		rb.exprs = append(rb.exprs,
			&Payload{
				DestRegister: 1,
				Base:         PayloadBaseTransportHeader,
				Offset:       0,
				Len:          1,
			},
		)
		rb = rb.inSet(set)
		rb.sets.Put(set.ID, NfSet{Set: set, Elements: elements})
	}
	return rb
}

func (rb ruleBuilder) ip4() ruleBuilder {
	rb.exprs = append(rb.exprs,
		&Meta{Key: MetaKeyNFPROTO, Register: 1},
		&Cmp{
			Op:       CmpOpEq,
			Register: 1,
			Data:     []byte{unix.NFPROTO_IPV4},
		}, //ip
	)
	return rb
}

func (rb ruleBuilder) ip6() ruleBuilder {
	rb.exprs = append(rb.exprs,
		&Meta{Key: MetaKeyNFPROTO, Register: 1},
		&Cmp{
			Op:       CmpOpEq,
			Register: 1,
			Data:     []byte{unix.NFPROTO_IPV6},
		}, //ip6
	)
	return rb
}

func (rb ruleBuilder) ctState(ctStateBitMask uint32) ruleBuilder {
	rb.exprs = append(rb.exprs,
		&Ct{Key: CtKeySTATE, Register: 1},
		&Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            4,
			Mask:           NativeEndian.PutUint32(ctStateBitMask),
			Xor:            NativeEndian.PutUint32(0),
		},
		&Cmp{
			Op:       CmpOpNeq,
			Data:     NativeEndian.PutUint32(0),
			Register: 1,
		},
	)
	return rb
}

func (rb ruleBuilder) iifname() ruleBuilder { //nolint:unused
	rb.exprs = append(rb.exprs,
		&Meta{Key: MetaKeyIIFNAME, Register: 1},
	)
	return rb
}

func (rb ruleBuilder) oifname() ruleBuilder { //nolint:unused
	rb.exprs = append(rb.exprs,
		&Meta{Key: MetaKeyOIFNAME, Register: 1},
	)
	return rb
}

func (rb ruleBuilder) neqS(s string) ruleBuilder { //nolint:unused
	rb.exprs = append(rb.exprs,
		&Cmp{
			Register: 1,
			Op:       CmpOpNeq,
			Data:     PutString(zeroEndedS(s)),
		},
	)
	return rb
}

func (rb ruleBuilder) eqU16(val uint16) ruleBuilder {
	return rb.cmpU16(CmpOpEq, val)
}
func (rb ruleBuilder) leU16(val uint16) ruleBuilder {
	return rb.cmpU16(CmpOpLte, val)
}
func (rb ruleBuilder) ltU16(val uint16) ruleBuilder { //nolint:unused
	return rb.cmpU16(CmpOpLt, val)
}
func (rb ruleBuilder) geU16(val uint16) ruleBuilder {
	return rb.cmpU16(CmpOpGte, val)
}
func (rb ruleBuilder) gtU16(val uint16) ruleBuilder { //nolint:unused
	return rb.cmpU16(CmpOpGt, val)
}
func (rb ruleBuilder) cmpU16(op CmpOp, val uint16) ruleBuilder {
	rb.exprs = append(rb.exprs, &Cmp{
		Register: 1,
		Op:       op,
		Data:     BigEndian.PutUint16(val),
	})
	return rb
}

func (rb ruleBuilder) eqS(s string) ruleBuilder { //nolint:unused
	rb.exprs = append(rb.exprs, &Cmp{
		Register: 1,
		Op:       CmpOpEq,
		Data:     PutString(zeroEndedS(s)),
	})
	return rb
}

func (rb ruleBuilder) metaNFTRACE(on bool) ruleBuilder {
	if on {
		rb.exprs = append(rb.exprs,
			&Immediate{
				Register: 1,
				Data:     []byte{1},
			},
			&Meta{
				Key:            MetaKeyNFTRACE,
				Register:       1,
				SourceRegister: true,
			}, //meta nftrace set 1|0
		)
	}
	return rb
}

func (rb ruleBuilder) srcOrDstSingleIpNet(n net.IPNet, isSource bool) ruleBuilder {
	var isIP4 bool
	switch len(n.IP) {
	case net.IPv4len:
		isIP4 = true
	case net.IPv6len:
	default:
		panic(
			errors.Errorf("wrong IPNet '%s'", n),
		)
	}
	set := NfSet{
		Elements: setsUtils{}.nets2SetElements(sli(n),
			tern(isIP4, iplib.IP4Version, iplib.IP6Version)),
		Set: &nftLib.Set{
			ID:        nextSetID(),
			Name:      "__set%d",
			Constant:  true,
			KeyType:   tern(isIP4, nftLib.TypeIPAddr, nftLib.TypeIP6Addr),
			Interval:  true,
			Anonymous: true,
		},
	}
	_ = rb.sets.Insert(set.ID, set)

	return tern(isSource,
		tern(isIP4, rb.saddr4, rb.saddr6),
		tern(isIP4, rb.daddr4, rb.daddr6),
	)().inSet(set.Set)
}

func (rb ruleBuilder) ndpi(dom model.FQDN, protocols ...string) ruleBuilder { //nolint:unused
	n, e := NewNdpi(NdpiWithHost(dom.String()), NdpiWithProtocols(protocols...))
	if e != nil {
		panic(e)
	}
	rb.exprs = append(rb.exprs, n)
	return rb
}
