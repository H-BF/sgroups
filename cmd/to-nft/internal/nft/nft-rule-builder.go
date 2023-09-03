package nft

import (
	"fmt"

	di "github.com/H-BF/sgroups/internal/dict"
	model "github.com/H-BF/sgroups/internal/models/sgroups"

	"github.com/c-robinson/iplib"
	nftlib "github.com/google/nftables"
	. "github.com/google/nftables/binaryutil"
	. "github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

func beginRule() ruleBuilder {
	return ruleBuilder{}
}

type ruleBuilder struct {
	sets  di.HDict[uint32, NfSet]
	exprs []Any
}

func (rb ruleBuilder) applyRule(chn *nftlib.Chain, c *nftlib.Conn) {
	if len(rb.exprs) > 0 {
		rb.sets.Iterate(func(id uint32, s NfSet) bool {
			s.Table = chn.Table
			if e := c.AddSet(s.Set, s.Elements); e != nil {
				panic(e)
			}
			return true
		})
		_ = c.AddRule(&nftlib.Rule{
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

func (rb ruleBuilder) inSet(s *nftlib.Set) ruleBuilder {
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
	panic("not impl")
}

func (rb ruleBuilder) daddr6() ruleBuilder {
	panic("not impl")
}

func (rb ruleBuilder) saddr4() ruleBuilder {
	rb.exprs = append(rb.ip4().exprs, //ip
		&Payload{
			DestRegister: 1,
			Base:         PayloadBaseNetworkHeader,
			Offset:       uint32(12), //nolint:gomnd
			Len:          uint32(4),  //nolint:gomnd
		}, //saddr
	)
	return rb
}

func (rb ruleBuilder) daddr4() ruleBuilder {
	rb.exprs = append(rb.ip4().exprs, //ip
		&Payload{
			DestRegister: 1,
			Base:         PayloadBaseNetworkHeader,
			Offset:       uint32(16), //nolint:gomnd
			Len:          uint32(4),  //nolint:gomnd
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

func (rb ruleBuilder) ipProto(tr model.NetworkTransport) ruleBuilder {
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

func (rb ruleBuilder) iifname() ruleBuilder {
	rb.exprs = append(rb.exprs,
		&Meta{Key: MetaKeyIIFNAME, Register: 1},
	)
	return rb
}

func (rb ruleBuilder) oifname() ruleBuilder {
	rb.exprs = append(rb.exprs,
		&Meta{Key: MetaKeyOIFNAME, Register: 1},
	)
	return rb
}

func (rb ruleBuilder) neqS(s string) ruleBuilder {
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
