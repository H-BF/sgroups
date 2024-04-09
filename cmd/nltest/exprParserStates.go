package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/H-BF/corlib/logger"
	nft "github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
	"net"
	"sort"
	"strconv"
)

type (
	parserState interface {
		parseMeta(meta *expr.Meta)
		parseCmp(cmp *expr.Cmp)
		parsePayload(payload *expr.Payload)
		parseLookup(lookup *expr.Lookup)
	}

	idleState struct {
		pctx *exprParserCtx
	}
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
		logger.Debugf(i.pctx.ctx, "unexpected Meta Key: %s", metaKey2string(meta.Key))
	}
}

func (i idleState) parseCmp(cmp *expr.Cmp) {
	//debug(i.pctx.debug)
}

func (i idleState) parsePayload(payload *expr.Payload) {
	debug(i.pctx.debug)
}

func (i idleState) parseLookup(lookup *expr.Lookup) {
	debug(i.pctx.debug)
}

type parseNFProto struct {
	pctx *exprParserCtx
}

func (p parseNFProto) parseMeta(meta *expr.Meta) {
	debug(p.pctx.debug)
}

func (p parseNFProto) parseCmp(cmp *expr.Cmp) {
	if len(cmp.Data) != 1 {
		p.pctx.toIdle()
		logger.Debugf(p.pctx.ctx, "nfproto wrong bytes count: %d", len(cmp.Data))
		return
	}
	switch cmp.Data[0] {
	case unix.NFPROTO_IPV4:
		p.pctx.setState(parseAddr{p.pctx, net.IPv4len})
	case unix.NFPROTO_IPV6:
		p.pctx.setState(parseAddr{p.pctx, net.IPv6len})
	default:
		p.pctx.toIdle()
		logger.Debugf(p.pctx.ctx, "unexpected NFPROTO family: %s", family2str(nft.TableFamily(cmp.Data[0])))
	}
}

func (p parseNFProto) parsePayload(payload *expr.Payload) {
	debug(p.pctx.debug)
}

func (p parseNFProto) parseLookup(lookup *expr.Lookup) {
	debug(p.pctx.debug)
}

type parseL4Proto struct {
	pctx *exprParserCtx
}

func (p parseL4Proto) parseMeta(meta *expr.Meta) {
	debug(p.pctx.debug)
}

func (p parseL4Proto) parseCmp(cmp *expr.Cmp) {
	if len(cmp.Data) != 1 {
		p.pctx.toIdle()
		logger.Debugf(p.pctx.ctx, "l4proto wrong bytes count: %d", len(cmp.Data))
		return
	}
	switch cmp.Data[0] {
	case unix.IPPROTO_TCP, unix.IPPROTO_UDP:
		p.pctx.setState(parsePorts{p.pctx})
	case unix.IPPROTO_ICMP, unix.IPPROTO_ICMPV6:
		// TODO: if we load `meta nftrace set 1 icmp type 100 drop` by nft cli then rule.Exprs will be differ
		p.pctx.setState(&skipICMP{pctx: p.pctx})
		logger.Debugf(p.pctx.ctx, "skiping icmp expressions")
	default:
		p.pctx.toIdle()
		logger.Debugf(p.pctx.ctx, "unexpected L4PROTO family: %v", cmp.Data)
	}
}

func (p parseL4Proto) parsePayload(payload *expr.Payload) {
	debug(p.pctx.debug)
}

func (p parseL4Proto) parseLookup(lookup *expr.Lookup) {
	debug(p.pctx.debug)
}

type skipICMP struct {
	pctx           *exprParserCtx
	payloadSkipped bool
}

func (s *skipICMP) parseMeta(meta *expr.Meta) {
	debug(s.pctx.debug)
}

func (s *skipICMP) parseCmp(cmp *expr.Cmp) {
	if !s.payloadSkipped {
		debug(s.pctx.debug)
	}
	s.pctx.toIdle()
}

func (s *skipICMP) parsePayload(payload *expr.Payload) {
	s.payloadSkipped = !s.payloadSkipped
	if !s.payloadSkipped {
		debug(s.pctx.debug)
	}
}

func (s *skipICMP) parseLookup(lookup *expr.Lookup) {
	if !s.payloadSkipped {
		debug(s.pctx.debug)
	}
	s.pctx.toIdle()
}

type parseAddr struct {
	pctx      *exprParserCtx
	ipVersion int
}

func (p parseAddr) parseMeta(meta *expr.Meta) {
	debug(p.pctx.debug)
}

func (p parseAddr) parseCmp(cmp *expr.Cmp) {
	debug(p.pctx.debug)
}

func (p parseAddr) parsePayload(payload *expr.Payload) {
	if payload.Base != expr.PayloadBaseNetworkHeader {
		p.pctx.toIdle()
		logger.Error(p.pctx.ctx, "payload trying parse IP from wrong header")
		return
	}
	switch p.ipVersion {
	case net.IPv4len:
		switch payload.Offset {
		case OffsetV4Saddr:
			p.pctx.setState(matchAddr{p.pctx, p.ipVersion, &p.pctx.rule.Addresses.Source})
		case OffsetV4Daddr:
			p.pctx.setState(matchAddr{p.pctx, p.ipVersion, &p.pctx.rule.Addresses.Destination})
		default:
			logger.Debugf(p.pctx.ctx, "unknown payload offset for ipv4 addr: %d", payload.Offset)
		}
	case net.IPv6len:
		switch payload.Offset {
		case OffsetV6Saddr:
			p.pctx.setState(matchAddr{p.pctx, p.ipVersion, &p.pctx.rule.Addresses.Source})
		case OffsetV6Daddr:
			p.pctx.setState(matchAddr{p.pctx, p.ipVersion, &p.pctx.rule.Addresses.Destination})
		default:
			logger.Debugf(p.pctx.ctx, "unknown payload offset for ipv6 addr: %d", payload.Offset)
		}
	}
}

func (p parseAddr) parseLookup(lookup *expr.Lookup) {
	debug(p.pctx.debug)
}

type matchAddr struct {
	pctx      *exprParserCtx
	ipVersion int
	arr       *[]string
}

func (c matchAddr) parseMeta(meta *expr.Meta) {
	debug(c.pctx.debug)
}

func (c matchAddr) parseCmp(cmp *expr.Cmp) {
	defer func() {
		c.pctx.toIdle()
	}()

	var data net.IP = make([]byte, c.ipVersion)
	copy(data, cmp.Data)
	*c.arr = append(*c.arr, data.String())
}

func (c matchAddr) parsePayload(payload *expr.Payload) {
	debug(c.pctx.debug)
}

func (c matchAddr) parseLookup(lookup *expr.Lookup) {
	defer func() {
		c.pctx.toIdle()
	}()

	set, ok := c.pctx.setMapping[lookup.SetName]
	if !ok {
		logger.Errorf(c.pctx.ctx, "set not found: %s", lookup.SetName)
		return
	}
	if !set.Anonymous {
		*c.arr = append(*c.arr, fmt.Sprintf("@%s", set.Name))
		return
	}

	nets, err := setElems2Nets(c.pctx.setElements[lookup.SetName])
	if err != nil {
		logger.Debugf(c.pctx.ctx, "Lookup parse err: %v", err)
	} else {
		*c.arr = append(*c.arr, nets...)
	}
}

type parsePorts struct {
	pctx *exprParserCtx
}

func (p parsePorts) parseMeta(meta *expr.Meta) {
	debug(p.pctx.debug)
}

func (p parsePorts) parseCmp(cmp *expr.Cmp) {
	debug(p.pctx.debug)
}

func (p parsePorts) parsePayload(payload *expr.Payload) {
	portsPayload(p.pctx, payload, func(p *exprParserCtx) parserState {
		return maybeMorePorts{p}
	})
}

func (p parsePorts) parseLookup(lookup *expr.Lookup) {
	debug(p.pctx.debug)
}

type matchPorts struct {
	pctx      *exprParserCtx
	ports     *[]string
	nextState func(pctx *exprParserCtx) parserState
}

func (m *matchPorts) parseMeta(meta *expr.Meta) {
	debug(m.pctx.debug)
}

func (m *matchPorts) parseCmp(cmp *expr.Cmp) {
	var port = binary.BigEndian.Uint16(cmp.Data)
	*m.ports = append(*m.ports, strconv.FormatUint(uint64(port), 10))
	if cmp.Op == expr.CmpOpEq || cmp.Op == expr.CmpOpLt || cmp.Op == expr.CmpOpLte {
		m.pctx.setState(m.nextState(m.pctx))
	}
}

func (m *matchPorts) parsePayload(payload *expr.Payload) {
	debug(m.pctx.debug)
}

func (m *matchPorts) parseLookup(lookup *expr.Lookup) {
	defer func() {
		m.pctx.setState(m.nextState(m.pctx))
	}()
	set, ok := m.pctx.setMapping[lookup.SetName]
	if !ok {
		logger.Errorf(m.pctx.ctx, "set not found: %s", lookup.SetName)
		return
	}
	if !set.Anonymous {
		*m.ports = append(*m.ports, set.Name)
		return
	}

	if set.Interval {
		var interval []byte
		els := m.pctx.setElements[lookup.SetName]
		sort.Slice(els, func(i, j int) bool {
			return bytes.Compare(els[i].Key, els[j].Key) < 0
		})
		for _, el := range els {
			if !el.IntervalEnd {
				if len(interval) != 0 {
					logger.Errorf(m.pctx.ctx, "element with IntervalEnd=true not found")
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
		for _, el := range m.pctx.setElements[lookup.SetName] {
			var port = binary.BigEndian.Uint16(el.Key)
			*m.ports = append(*m.ports, strconv.FormatUint(uint64(port), 10))
		}
	}
}

type maybeMorePorts struct {
	pctx *exprParserCtx
}

func (m maybeMorePorts) parseMeta(meta *expr.Meta) {
	debug(m.pctx.debug)
}

func (m maybeMorePorts) parseCmp(cmp *expr.Cmp) {
	debug(m.pctx.debug)
}

func (m maybeMorePorts) parsePayload(payload *expr.Payload) {
	portsPayload(m.pctx, payload, func(p *exprParserCtx) parserState {
		return p.idleState
	})
}

func (m maybeMorePorts) parseLookup(lookup *expr.Lookup) {
	debug(m.pctx.debug)
}

func portsPayload(pctx *exprParserCtx, payload *expr.Payload, nextStateCb func(p *exprParserCtx) parserState) {
	if payload.Base != expr.PayloadBaseTransportHeader {
		pctx.toIdle()
		logger.Error(pctx.ctx, "payload trying parse ports from wrong header")
		return
	}
	switch payload.Offset {
	case OffsetSport:
		pctx.setState(&matchPorts{pctx, &pctx.rule.Ports.Source, nextStateCb})
	case OffsetDport:
		pctx.setState(&matchPorts{pctx, &pctx.rule.Ports.Destination, nextStateCb})
	default:
		logger.Debugf(pctx.ctx, "unknown payload offset for ports: %d", payload.Offset)
	}
}

func debug(d bool) {
	if d {
		panic("implement me")
	}
}
