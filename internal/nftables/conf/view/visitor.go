package view

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"

	dkt "github.com/H-BF/sgroups/internal/dict"
	"github.com/H-BF/sgroups/internal/nftables/conf"
	hlp "github.com/H-BF/sgroups/internal/nftables/helpers"

	nft "github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

type ruleExprVisitor interface {
	visitMeta(meta *expr.Meta) (ruleExprVisitor, error)
	visitCmp(cmp *expr.Cmp) (ruleExprVisitor, error)
	visitPayload(payload *expr.Payload) (ruleExprVisitor, error)
	visitLookup(lookup *expr.Lookup, setsState dkt.HDict[string, conf.NfSet]) (ruleExprVisitor, error)
}

// initialVisitor - initial visitor for group of Expression from which we can get meaningful information
type initialVisitor struct {
	view *RuleView
}

var _ ruleExprVisitor = (*initialVisitor)(nil)

func (i initialVisitor) visitMeta(meta *expr.Meta) (ruleExprVisitor, error) {
	switch meta.Key {
	case expr.MetaKeyNFPROTO:
		return nfProtoVisitor{i.view}, nil
	case expr.MetaKeyL4PROTO:
		return l4ProtoVisitor{i.view}, nil
	case expr.MetaKeyIIFNAME:
	case expr.MetaKeyOIFNAME:
	default:
		return i, nil
	}
	return i, nil
}

func (i initialVisitor) visitCmp(_ *expr.Cmp) (ruleExprVisitor, error) {
	// skip rules like `ct state established`
	return i, nil
}

func (i initialVisitor) visitPayload(_ *expr.Payload) (ruleExprVisitor, error) {
	// noop here
	return i, nil
}

func (i initialVisitor) visitLookup(_ *expr.Lookup, _ dkt.HDict[string, conf.NfSet]) (ruleExprVisitor, error) {
	// noop here
	return i, nil
}

type nfProtoVisitor struct {
	view *RuleView
}

var _ ruleExprVisitor = (*nfProtoVisitor)(nil)

func (p nfProtoVisitor) visitMeta(_ *expr.Meta) (ruleExprVisitor, error) {
	return nil, errors.New("unexpected Meta in nfProtoVisitor")
}

func (p nfProtoVisitor) visitCmp(cmp *expr.Cmp) (ruleExprVisitor, error) {
	if len(cmp.Data) != 1 {
		return nil, fmt.Errorf("nfproto wrong bytes count: %d", len(cmp.Data))
	}
	switch cmp.Data[0] {
	case unix.NFPROTO_IPV4:
		return detectAddrVisitor{p.view, net.IPv4len}, nil
	case unix.NFPROTO_IPV6:
		return detectAddrVisitor{p.view, net.IPv6len}, nil
	default:
		return nil, fmt.Errorf("unexpected NFPROTO family: %s", hlp.TableFamily2S(nft.TableFamily(cmp.Data[0])))
	}
}

func (p nfProtoVisitor) visitPayload(_ *expr.Payload) (ruleExprVisitor, error) {
	return nil, errors.New("unexpected Payload in nfProtoVisitor")
}

func (p nfProtoVisitor) visitLookup(_ *expr.Lookup, _ dkt.HDict[string, conf.NfSet]) (ruleExprVisitor, error) {
	return nil, errors.New("unexpected Lookup in nfProtoVisitor")
}

type l4ProtoVisitor struct {
	view *RuleView
}

var _ ruleExprVisitor = (*l4ProtoVisitor)(nil)

func (p l4ProtoVisitor) visitMeta(_ *expr.Meta) (ruleExprVisitor, error) {
	return nil, errors.New("unexpected Meta in l4ProtoVisitor")
}

func (p l4ProtoVisitor) visitCmp(cmp *expr.Cmp) (ruleExprVisitor, error) {
	if len(cmp.Data) != 1 {
		return nil, fmt.Errorf("l4proto wrong bytes count: %d", len(cmp.Data))
	}
	switch cmp.Data[0] {
	case unix.IPPROTO_TCP, unix.IPPROTO_UDP:
		return detectPortsVisitor{p.view}, nil
	case unix.IPPROTO_ICMP, unix.IPPROTO_ICMPV6:
		// TODO: if we load `meta nftrace set 1 icmp type 100 drop` by nft cli then rule.Exprs will be differ
		return skipICMPVisitor{view: p.view}, nil
	default:
		return initialVisitor{p.view}, nil
	}
}

func (p l4ProtoVisitor) visitPayload(_ *expr.Payload) (ruleExprVisitor, error) {
	return nil, errors.New("unexpected Payload in l4ProtoVisitor")
}

func (p l4ProtoVisitor) visitLookup(_ *expr.Lookup, _ dkt.HDict[string, conf.NfSet]) (ruleExprVisitor, error) {
	return nil, errors.New("unexpected Lookup in l4ProtoVisitor")
}

// skipICMPVisitor - should skip sentence of [meta load l4proto], [cmp eq], [payload load], [cmp eq | lookup]
type skipICMPVisitor struct {
	view           *RuleView
	payloadSkipped bool
}

var _ ruleExprVisitor = (*skipICMPVisitor)(nil)

func (s skipICMPVisitor) visitMeta(_ *expr.Meta) (ruleExprVisitor, error) {
	return s, nil
}

func (s skipICMPVisitor) visitCmp(_ *expr.Cmp) (ruleExprVisitor, error) {
	if s.payloadSkipped {
		return initialVisitor{s.view}, nil
	}
	return s, nil
}

func (s skipICMPVisitor) visitPayload(_ *expr.Payload) (ruleExprVisitor, error) {
	s.payloadSkipped = true
	return s, nil
}

func (s skipICMPVisitor) visitLookup(_ *expr.Lookup, _ dkt.HDict[string, conf.NfSet]) (ruleExprVisitor, error) {
	if s.payloadSkipped {
		return initialVisitor{s.view}, nil
	}
	return s, nil
}

type detectAddrVisitor struct {
	view      *RuleView
	ipVersion int
}

var _ ruleExprVisitor = (*detectAddrVisitor)(nil)

func (p detectAddrVisitor) visitMeta(meta *expr.Meta) (ruleExprVisitor, error) {
	// if face with meta here it probably icmp sentence
	return initialVisitor{p.view}.visitMeta(meta)
}

func (p detectAddrVisitor) visitCmp(_ *expr.Cmp) (ruleExprVisitor, error) {
	return nil, errors.New("unexpected Cmp in detectAddrVisitor")
}

func (p detectAddrVisitor) visitPayload(payload *expr.Payload) (ruleExprVisitor, error) {
	if payload.Base != expr.PayloadBaseNetworkHeader {
		return nil, errors.New("trying IP Payload from wrong header in detectAddrVisitor")
	}
	switch p.ipVersion {
	case net.IPv4len:
		switch payload.Offset {
		case hlp.OffsetSAddrV4:
			return matchAddrVisitor{p.view, p.ipVersion, &p.view.Addresses.Source}, nil
		case hlp.OffsetDAddrV4:
			return matchAddrVisitor{p.view, p.ipVersion, &p.view.Addresses.Destination}, nil
		default:
			return nil, fmt.Errorf("unknown payload offset for ipv4 addr: %d in detectAddrVisitor", payload.Offset)
		}
	case net.IPv6len:
		switch payload.Offset {
		case hlp.OffsetSAddrV6:
			return matchAddrVisitor{p.view, p.ipVersion, &p.view.Addresses.Source}, nil
		case hlp.OffsetDAddrV6:
			return matchAddrVisitor{p.view, p.ipVersion, &p.view.Addresses.Destination}, nil
		default:
			return nil, fmt.Errorf("unknown payload offset for ipv4 addr: %d in detectAddrVisitor", payload.Offset)
		}
	}
	return nil, errors.New("ip version didn't match in detectAddrVisitor")
}

func (p detectAddrVisitor) visitLookup(_ *expr.Lookup, _ dkt.HDict[string, conf.NfSet]) (ruleExprVisitor, error) {
	return nil, errors.New("unexpected Lookup in detectAddrVisitor")
}

type matchAddrVisitor struct {
	view      *RuleView
	ipVersion int
	arr       *[]string
}

var _ ruleExprVisitor = (*matchAddrVisitor)(nil)

func (m matchAddrVisitor) visitMeta(_ *expr.Meta) (ruleExprVisitor, error) {
	return nil, errors.New("unexpected Meta in matchAddrVisitor")
}

func (m matchAddrVisitor) visitCmp(cmp *expr.Cmp) (ruleExprVisitor, error) {
	var data net.IP = make([]byte, m.ipVersion)
	copy(data, cmp.Data)
	*m.arr = append(*m.arr, data.String())
	return initialVisitor{m.view}, nil
}

func (m matchAddrVisitor) visitPayload(_ *expr.Payload) (ruleExprVisitor, error) {
	return nil, errors.New("unexpected Payload in matchAddrVisitor")
}

func (m matchAddrVisitor) visitLookup(lookup *expr.Lookup, setsState dkt.HDict[string, conf.NfSet]) (ruleExprVisitor, error) {
	set, ok := setsState.Get(lookup.SetName)
	if !ok {
		return nil, fmt.Errorf("set not found: %s", lookup.SetName)
	}
	if !set.Anonymous {
		*m.arr = append(*m.arr, fmt.Sprintf("@%s", set.Name))
	} else {
		nets, err := setElems2Nets(set.Elements)
		if err != nil {
			return nil, fmt.Errorf("setElems2Nets err: %v in matchAddrVisitor", err)
		}
		*m.arr = append(*m.arr, nets...)
	}
	return initialVisitor{m.view}, nil
}

type detectPortsVisitor struct {
	view *RuleView
}

var _ ruleExprVisitor = (*detectPortsVisitor)(nil)

func (p detectPortsVisitor) visitMeta(_ *expr.Meta) (ruleExprVisitor, error) {
	return nil, errors.New("unexpected Meta in detectPortsVisitor")
}

func (p detectPortsVisitor) visitCmp(_ *expr.Cmp) (ruleExprVisitor, error) {
	return nil, errors.New("unexpected Cmp in detectPortsVisitor")
}

func (p detectPortsVisitor) visitPayload(payload *expr.Payload) (ruleExprVisitor, error) {
	return portsPayload(payload, p.view, func() ruleExprVisitor {
		return maybeMorePortsVisitor{p.view}
	})
}

func (p detectPortsVisitor) visitLookup(_ *expr.Lookup, _ dkt.HDict[string, conf.NfSet]) (ruleExprVisitor, error) {
	return nil, errors.New("unexpected Lookup in detectPortsVisitor")
}

type matchPortsVisitor struct {
	view      *RuleView
	ports     *[]string
	nextState func() ruleExprVisitor
}

var _ ruleExprVisitor = (*matchPortsVisitor)(nil)

func (m matchPortsVisitor) visitMeta(_ *expr.Meta) (ruleExprVisitor, error) {
	return nil, errors.New("unexpected Meta in matchPortsVisitor")
}

func (m matchPortsVisitor) visitCmp(cmp *expr.Cmp) (ruleExprVisitor, error) {
	var port = binary.BigEndian.Uint16(cmp.Data)
	*m.ports = append(*m.ports, strconv.FormatUint(uint64(port), 10))

	// after Cmp can follow one more Cmp here check it
	if cmp.Op == expr.CmpOpEq || cmp.Op == expr.CmpOpLt || cmp.Op == expr.CmpOpLte {
		return m.nextState(), nil
	}
	return m, nil
}

func (m matchPortsVisitor) visitPayload(_ *expr.Payload) (ruleExprVisitor, error) {
	return nil, errors.New("unexpected Payload in matchPortsVisitor")
}

func (m matchPortsVisitor) visitLookup(lookup *expr.Lookup, setsState dkt.HDict[string, conf.NfSet]) (ruleExprVisitor, error) {
	set, ok := setsState.Get(lookup.SetName)
	if !ok {
		return nil, fmt.Errorf("set not found: %s", lookup.SetName)
	}
	if !set.Anonymous {
		*m.ports = append(*m.ports, set.Name)
		return m.nextState(), nil
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
					return nil, errors.New("element with IntervalEnd=true not found")
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
	return m.nextState(), nil
}

type maybeMorePortsVisitor struct {
	view *RuleView
}

var _ ruleExprVisitor = (*maybeMorePortsVisitor)(nil)

func (m maybeMorePortsVisitor) visitMeta(_ *expr.Meta) (ruleExprVisitor, error) {
	return nil, errors.New("unexpected Meta in maybeMorePortsVisitor")
}

func (m maybeMorePortsVisitor) visitCmp(_ *expr.Cmp) (ruleExprVisitor, error) {
	return nil, errors.New("unexpected Cmp in maybeMorePortsVisitor")
}

func (m maybeMorePortsVisitor) visitPayload(payload *expr.Payload) (ruleExprVisitor, error) {
	return portsPayload(payload, m.view, func() ruleExprVisitor {
		return initialVisitor{m.view}
	})
}

func (m maybeMorePortsVisitor) visitLookup(_ *expr.Lookup, _ dkt.HDict[string, conf.NfSet]) (ruleExprVisitor, error) {
	return nil, errors.New("unexpected Lookup in maybeMorePortsVisitor")
}

func portsPayload(payload *expr.Payload, view *RuleView, nextStateCb func() ruleExprVisitor) (ruleExprVisitor, error) {
	if payload.Base != expr.PayloadBaseTransportHeader {
		return nil, errors.New("trying ports Payload from wrong header in portsPayload")
	}
	switch payload.Offset {
	case hlp.OffsetSPort:
		return matchPortsVisitor{view, &view.Ports.Source, nextStateCb}, nil
	case hlp.OffsetDPort:
		return matchPortsVisitor{view, &view.Ports.Destination, nextStateCb}, nil
	default:
		return nil, fmt.Errorf("unknown payload offset for ports: %d", payload.Offset)
	}
}
