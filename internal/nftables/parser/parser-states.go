package parser

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"sort"
	"strconv"

	hlp "github.com/H-BF/sgroups/internal/nftables/helpers"

	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

type (
	parserState interface {
		parseMeta(meta *expr.Meta)
		parseCmp(cmp *expr.Cmp)
		parsePayload(payload *expr.Payload)
		parseLookup(lookup *expr.Lookup)
	}
	//^^^^^^^^^^^^^^ вот это - КОШКУ внезапно обозвали ОБЕЗЬЯНОЙ ^^^^^^

	idleState struct {
		pctx *exprParserCtx
	}

	/*// !!!! TODO: переписать код в концепции паттерна Visitor !!!!
	nftableVisitor interface {
		visitMeta(*expr.Meta) error
		visitCmp(*expr.Cmp) error
		visitPayload(*expr.Payload) error
		visitLookup(*expr.Lookup) error
		// ^^^---- может что-то еще добавить?
	}
	*/

)

func (i idleState) parseMeta(meta *expr.Meta) {
	switch meta.Key {
	case expr.MetaKeyNFPROTO:
		i.pctx.setState(parseNFProto{i.pctx})
	case expr.MetaKeyL4PROTO:
		i.pctx.setState(parseL4Proto{i.pctx})
	case expr.MetaKeyIIFNAME:
	case expr.MetaKeyOIFNAME:
	default:
		//i.pctx.debug("unexpected Meta Key: %s", hlp.MetaKey2S(meta.Key))
		// ^^^^^^ не логируем а отправляем внятную ошибку
	}
}

func (i idleState) parseCmp(_ *expr.Cmp) {
	// skip rules like `ct state established`
}

func (i idleState) parsePayload(_ *expr.Payload) {
	noop()
}

func (i idleState) parseLookup(_ *expr.Lookup) {
	noop()
}

type parseNFProto struct {
	pctx *exprParserCtx
}

func (p parseNFProto) parseMeta(_ *expr.Meta) {
	noop()
}

func (p parseNFProto) parseCmp(cmp *expr.Cmp) {
	if len(cmp.Data) != 1 {
		p.pctx.setState(idleState{p.pctx})
		//p.pctx.debug("nfproto wrong bytes count: %d", len(cmp.Data))
		// ^^^^^^ не логируем а отправляем внятную ошибку
		return
	}
	switch cmp.Data[0] {
	case unix.NFPROTO_IPV4:
		p.pctx.setState(parseAddr{p.pctx, net.IPv4len})
	case unix.NFPROTO_IPV6:
		p.pctx.setState(parseAddr{p.pctx, net.IPv6len})
	default:
		p.pctx.setState(idleState{p.pctx})
		//p.pctx.debug("unexpected NFPROTO family: %s", hlp.TableFamily2S(nft.TableFamily(cmp.Data[0])))
		// ^^^^^^ не логируем а отправляем внятную ошибку
	}
}

func (p parseNFProto) parsePayload(_ *expr.Payload) {
	noop()
}

func (p parseNFProto) parseLookup(_ *expr.Lookup) {
	noop()
}

type parseL4Proto struct {
	pctx *exprParserCtx
}

func (p parseL4Proto) parseMeta(_ *expr.Meta) {
	noop()
}

func (p parseL4Proto) parseCmp(cmp *expr.Cmp) {
	if len(cmp.Data) != 1 {
		p.pctx.setState(idleState{p.pctx})
		//p.pctx.debug("l4proto wrong bytes count: %d", len(cmp.Data))
		return
	}
	switch cmp.Data[0] {
	case unix.IPPROTO_TCP, unix.IPPROTO_UDP:
		p.pctx.setState(parsePorts{p.pctx})
	case unix.IPPROTO_ICMP, unix.IPPROTO_ICMPV6:
		// TODO: if we load `meta nftrace set 1 icmp type 100 drop` by nft cli then rule.Exprs will be differ
		p.pctx.setState(&skipICMP{pctx: p.pctx})
		//p.pctx.debug("skiping icmp expressions")
		// ^^^^^^ не логируем а отправляем внятную ошибку
	default:
		p.pctx.setState(idleState{p.pctx})
		//p.pctx.debug("unexpected L4PROTO family: %v", cmp.Data)
		// ^^^^^^ не логируем а отправляем внятную ошибку
	}
}

func (p parseL4Proto) parsePayload(_ *expr.Payload) {
	noop()
}

func (p parseL4Proto) parseLookup(_ *expr.Lookup) {
	noop()
}

type skipICMP struct {
	pctx           *exprParserCtx
	payloadSkipped bool
}

func (s *skipICMP) parseMeta(_ *expr.Meta) {
	noop()
}

func (s *skipICMP) parseCmp(_ *expr.Cmp) {
	if !s.payloadSkipped {
		noop()
	}
	s.pctx.setState(idleState{s.pctx})
}

func (s *skipICMP) parsePayload(_ *expr.Payload) {
	s.payloadSkipped = !s.payloadSkipped
	if !s.payloadSkipped {
		noop()
	}
}

func (s *skipICMP) parseLookup(_ *expr.Lookup) {
	if !s.payloadSkipped {
		noop()
	}
	s.pctx.setState(idleState{s.pctx})
}

type parseAddr struct {
	pctx      *exprParserCtx
	ipVersion int
}

func (p parseAddr) parseMeta(_ *expr.Meta) {
	noop()
}

func (p parseAddr) parseCmp(_ *expr.Cmp) {
	noop()
}

func (p parseAddr) parsePayload(payload *expr.Payload) {
	if payload.Base != expr.PayloadBaseNetworkHeader {
		p.pctx.setState(idleState{p.pctx})
		//p.pctx.debug("payload trying parse IP from wrong header")
		// ^^^^^^ не логируем а отправляем внятную ошибку
		return
	}
	switch p.ipVersion {
	case net.IPv4len:
		switch payload.Offset {
		case hlp.OffsetSAddrV4:
			p.pctx.setState(matchAddr{p.pctx, p.ipVersion, &p.pctx.rule.Addresses.Source})
		case hlp.OffsetDAddrV4:
			p.pctx.setState(matchAddr{p.pctx, p.ipVersion, &p.pctx.rule.Addresses.Destination})
		default:
			//p.pctx.debug("unknown payload offset for ipv4 addr: %d", payload.Offset)
		}
	case net.IPv6len:
		switch payload.Offset {
		case hlp.OffsetSAddrV6:
			p.pctx.setState(matchAddr{p.pctx, p.ipVersion, &p.pctx.rule.Addresses.Source})
		case hlp.OffsetDAddrV6:
			p.pctx.setState(matchAddr{p.pctx, p.ipVersion, &p.pctx.rule.Addresses.Destination})
		default:
			//p.pctx.debug("unknown payload offset for ipv6 addr: %d", payload.Offset)
			// ^^^^^^ не логируем а отправляем внятную ошибку
		}
	}
}

func (p parseAddr) parseLookup(_ *expr.Lookup) {
	noop()
}

type matchAddr struct {
	pctx      *exprParserCtx
	ipVersion int
	arr       *[]string
}

func (m matchAddr) parseMeta(_ *expr.Meta) {
	noop()
}

func (m matchAddr) parseCmp(cmp *expr.Cmp) {
	defer func() {
		m.pctx.setState(idleState{m.pctx})
	}()

	var data net.IP = make([]byte, m.ipVersion)
	copy(data, cmp.Data)
	*m.arr = append(*m.arr, data.String())
}

func (m matchAddr) parsePayload(_ *expr.Payload) {
	noop()
}

func (m matchAddr) parseLookup(lookup *expr.Lookup) {
	defer func() {
		m.pctx.setState(idleState{m.pctx})
	}()

	set, ok := m.pctx.setsState.Get(lookup.SetName)
	if !ok {
		//m.pctx.error("set not found: %s", lookup.SetName)
		// ^^^^^^ не логируем а отправляем внятную ошибку
		return
	}
	if !set.Anonymous {
		*m.arr = append(*m.arr, fmt.Sprintf("@%s", set.Name))
		return
	}

	nets, err := setElems2Nets(set.Elements)
	if err != nil {
		//m.pctx.debug("Lookup parse err: %v", err)
		// ^^^^^^ не логируем а отправляем внятную ошибку
	} else {
		*m.arr = append(*m.arr, nets...)
	}
}

type parsePorts struct {
	pctx *exprParserCtx
}

func (p parsePorts) parseMeta(_ *expr.Meta) {
	noop()
}

func (p parsePorts) parseCmp(_ *expr.Cmp) {
	noop()
}

func (p parsePorts) parsePayload(payload *expr.Payload) {
	portsPayload(p.pctx, payload, func(p *exprParserCtx) parserState {
		return maybeMorePorts{p}
	})
}

func (p parsePorts) parseLookup(_ *expr.Lookup) {
	noop()
}

type matchPorts struct {
	pctx      *exprParserCtx
	ports     *[]string
	nextState func(pctx *exprParserCtx) parserState
}

func (m *matchPorts) parseMeta(_ *expr.Meta) {
	noop()
}

func (m *matchPorts) parseCmp(cmp *expr.Cmp) {
	var port = binary.BigEndian.Uint16(cmp.Data)
	*m.ports = append(*m.ports, strconv.FormatUint(uint64(port), 10))
	if cmp.Op == expr.CmpOpEq || cmp.Op == expr.CmpOpLt || cmp.Op == expr.CmpOpLte {
		m.pctx.setState(m.nextState(m.pctx))
	}
}

func (m *matchPorts) parsePayload(_ *expr.Payload) {
	noop()
}

func (m *matchPorts) parseLookup(lookup *expr.Lookup) {
	defer func() {
		m.pctx.setState(m.nextState(m.pctx))
	}()
	set, ok := m.pctx.setsState.Get(lookup.SetName)
	if !ok {
		//m.pctx.error("set not found: %s", lookup.SetName)
		// ^^^^^^ не логируем а отправляем внятную ошибку
		return
	}
	if !set.Anonymous {
		*m.ports = append(*m.ports, set.Name)
		return
	}

	if set.Interval {
		var interval []byte
		els := set.Elements
		sort.Slice(els, func(i, j int) bool {
			return bytes.Compare(els[i].Key, els[j].Key) < 0
		})
		for _, el := range els {
			if !el.IntervalEnd {
				if len(interval) != 0 {
					//m.pctx.error("element with IntervalEnd=true not found")
					// ^^^^^^ не логируем а отправляем внятную ошибку
					break
				}
				interval = el.Key
				continue
			}
			var port = binary.BigEndian.Uint16(interval)
			*m.ports = append(*m.ports, strconv.FormatUint(uint64(port), 10))
			var portEnd = binary.BigEndian.Uint16(el.Key)
			if portEnd-port > 1 {
				*m.ports = append(*m.ports, strconv.FormatUint(uint64(portEnd-1), 10))
			}
			interval = nil
		}
	} else {
		for _, el := range set.Elements {
			var port = binary.BigEndian.Uint16(el.Key)
			*m.ports = append(*m.ports, strconv.FormatUint(uint64(port), 10))
		}
	}
}

type maybeMorePorts struct {
	pctx *exprParserCtx
}

func (m maybeMorePorts) parseMeta(_ *expr.Meta) {
	noop()
}

func (m maybeMorePorts) parseCmp(_ *expr.Cmp) {
	noop()
}

func (m maybeMorePorts) parsePayload(payload *expr.Payload) {
	portsPayload(m.pctx, payload, func(p *exprParserCtx) parserState {
		return idleState{p}
	})
}

func (m maybeMorePorts) parseLookup(_ *expr.Lookup) {
	noop()
}

func portsPayload(pctx *exprParserCtx, payload *expr.Payload, nextStateCb func(p *exprParserCtx) parserState) {
	if payload.Base != expr.PayloadBaseTransportHeader {
		pctx.setState(idleState{pctx})
		//pctx.error("payload trying parse ports from wrong header")
		// ^^^^^^ не логируем а отправляем внятную ошибку
		return
	}
	switch payload.Offset {
	case hlp.OffsetSPort:
		pctx.setState(&matchPorts{pctx, &pctx.rule.Ports.Source, nextStateCb})
	case hlp.OffsetDPort:
		pctx.setState(&matchPorts{pctx, &pctx.rule.Ports.Destination, nextStateCb})
	default:
		//pctx.debug("unknown payload offset for ports: %d", payload.Offset)
		// ^^^^^^ не логируем тут а отправляем внятную ошибку
	}
}

func noop() {}

// ^^^^^^^^^^^^^^ что это за дичь?
