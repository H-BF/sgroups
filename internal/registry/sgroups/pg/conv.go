package pg

import (
	"math"
	"strings"

	"github.com/H-BF/sgroups/internal/dict"
	sgm "github.com/H-BF/sgroups/internal/models/sgroups"

	"github.com/H-BF/corlib/pkg/ranges"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/pkg/errors"
)

// ToModel -
func (o SG) ToModel() (sgm.SecurityGroup, error) {
	ret := sgm.SecurityGroup{
		Name:     o.Name,
		Networks: o.Networks,
		Logs:     o.Logs,
		Trace:    o.Trace,
	}
	err := ret.DefaultAction.FromString(string(o.DefaultAction))
	return ret, err
}

// FromModel -
func (o *SG) FromModel(m sgm.SecurityGroup) {
	o.Name = m.Name
	o.Networks = m.Networks
	o.Logs = m.Logs
	o.Trace = m.Trace
	o.DefaultAction = ChainDefaultAction(
		strings.ToUpper(m.DefaultAction.String()),
	)
}

// ToModel -
func (o PortRange) ToModel(allowNull bool) (sgm.PortRange, error) {
	if o.IsNull() {
		if allowNull {
			return nil, nil
		}
		return nil, errors.New("we got unexpected null port range from PG")
	}
	if o.Lower < 0 || o.Lower > o.Upper || o.Upper > PortMumber(^sgm.PortNumber(0)) {
		return nil, errors.Errorf("we got invalid invalid port range from PG: %v - %v", o.Lower, o.Upper)
	}
	var (
		retA sgm.PortNumber
		retB sgm.PortNumber
		retL bool
		retR bool
	)
	bounds := []struct {
		rB *sgm.PortNumber
		rT *bool
		sB PortMumber
		sT pgtype.BoundType
	}{
		{&retA, &retL, o.Lower, o.LowerType},
		{&retB, &retR, o.Upper, o.UpperType},
	}
	for _, n := range bounds {
		switch n.sT {
		case pgtype.Inclusive:
		case pgtype.Exclusive:
			*n.rT = true
		default:
			return nil, errors.Errorf("we got unexpected type of port range bound '%s' from PG", n.sT)
		}
		*n.rB = sgm.PortNumber(n.sB)
	}
	ret := sgm.PortRangeFactory.Range(retA, retL, retB, retR)
	err := sgm.ValidatePortRange(ret, false)
	return ret, err
}

// FromModel -
func (o *PortRange) FromModel(m sgm.PortRange, allowNull bool) error {
	if m == nil || m.IsNull() && !allowNull {
		if allowNull {
			o.Valid = false
			return nil
		}
		return errors.WithMessage(sgm.ErrUnexpectedNullPortRange, "PG cannot adopt such port range")
	}

	a, b := m.Bounds()

	v, ex := a.GetValue()
	o.Lower, o.LowerType = PortMumber(v), pgtype.Inclusive
	if ex {
		o.LowerType = pgtype.Exclusive
	}
	v, ex = b.GetValue()
	o.Upper, o.UpperType = PortMumber(v), pgtype.Inclusive
	if ex {
		o.UpperType = pgtype.Exclusive
	}
	o.Valid = true
	return nil
}

// FromModel -
func (o *PortMultirange) FromModel(m sgm.PortRanges) error {
	o.Multirange = nil
	var err error
	m.Iterate(func(r sgm.PortRange) bool {
		var pr PortRange
		if err = pr.FromModel(r, false); err == nil {
			o.Multirange = append(o.Multirange, pr)
		}
		return err == nil
	})
	return err
}

// ToModel -
func (o PortMultirange) ToModel() (sgm.PortRanges, error) {
	ret := ranges.NewMultiRange(sgm.PortRangeFactory)
	rr := make([]sgm.PortRange, 0, len(o.Multirange))
	for _, pr := range o.Multirange {
		r, e := pr.ToModel(false)
		if e != nil {
			return ret, e
		}
		rr = append(rr, r)
	}
	ret.Update(ranges.CombineMerge, rr...)
	return ret, nil
}

// FromModel -
func (o *SgRulePorts) FromModel(m sgm.SGRulePorts) error {
	err := o.S.FromModel(m.S)
	if err != nil {
		return errors.WithMessage(err, "PG cannot adopt such 'S' ports")
	}
	err = o.D.FromModel(m.D)
	return errors.WithMessage(err, "PG cannot adopt such 'D' ports")
}

// ToModel -
func (o SgRulePorts) ToModel() (sgm.SGRulePorts, error) {
	var ret sgm.SGRulePorts
	var err error
	if ret.D, err = o.D.ToModel(); err != nil {
		return ret, errors.WithMessage(err, "we got bad 'D' ports from PG")
	}
	ret.S, err = o.S.ToModel()
	return ret, errors.WithMessage(err, "we got bad 'S' ports from PG")
}

// ToModel -
func (o SgRulePortsArray) ToModel() ([]sgm.SGRulePorts, error) {
	var ret []sgm.SGRulePorts
	for _, item := range o {
		p, err := item.ToModel()
		if err != nil {
			return ret, err
		}
		ret = append(ret, p)
	}
	return ret, nil
}

// FromModel -
func (o *SgRulePortsArray) FromModel(m []sgm.SGRulePorts) error {
	if len(m) == 0 {
		*o = nil
		return nil
	}
	*o = make(SgRulePortsArray, 0, len(m))
	for _, item := range m {
		var x SgRulePorts
		err := x.S.FromModel(item.S)
		if err != nil {
			return errors.WithMessagef(err, "PG cannot adopt 'S' ports(%s)", item.S)
		}
		if err = x.D.FromModel(item.D); err != nil {
			return errors.WithMessagef(err, "PG cannot adopt 'D' ports(%s)", item.D)
		}
		*o = append(*o, x)
	}
	return nil
}

// ToModel -
func (o Proto) ToModel() (sgm.NetworkTransport, error) {
	v, ok := proto2modelProto[string(o)]
	if !ok {
		return 0, errors.Errorf("we got unknown proto '%s' from PG", o)
	}
	return v, nil
}

// FromModel -
func (o *Proto) FromModel(m sgm.NetworkTransport) error {
	v, ok := modelProto2proto[m]
	if !ok {
		return errors.Errorf("PG cannot adopt unknown proto(%v)", m)
	}
	*o = Proto(v)
	return nil
}

// ToModel -
func (o SGRule) ToModel() (sgm.SGRule, error) {
	var ret sgm.SGRule
	var err error
	ret.ID.SgFrom = o.SgFrom
	ret.ID.SgTo = o.SgTo
	if ret.ID.Transport, err = o.Proto.ToModel(); err != nil {
		return ret, err
	}
	if err = ret.Action.FromString(string(o.Action)); err != nil {
		return ret, err
	}
	ret.Logs = o.Logs
	ret.Ports, err = o.Ports.ToModel()
	return ret, err
}

// FromModel -
func (o *SGRule) FromModel(m sgm.SGRule) error {
	o.SgFrom = m.ID.SgFrom
	o.SgTo = m.ID.SgTo
	if err := o.Proto.FromModel(m.ID.Transport); err != nil {
		return err
	}
	if err := o.Ports.FromModel(m.Ports); err != nil {
		return err
	}
	o.Logs = m.Logs
	o.Action = ChainDefaultAction(strings.ToUpper(m.Action.String()))
	return nil
}

// ToModel -
func (o SG2FQDNRule) ToModel() (sgm.FQDNRule, error) {
	var ret sgm.FQDNRule
	var err error
	for _, p := range o.NdpiProtocols {
		_ = ret.NdpiProtocols.Insert(dict.StringCiKey(p))
	}
	ret.ID.SgFrom = o.SgFrom
	ret.ID.FqdnTo = sgm.FQDN(string(o.FqndTo))
	if ret.ID.Transport, err = o.Proto.ToModel(); err != nil {
		return ret, err
	}
	if err = ret.Action.FromString(string(o.Action)); err != nil {
		return ret, err
	}
	ret.Logs = o.Logs
	ret.Ports, err = o.Ports.ToModel()
	return ret, err
}

// FromModel -
func (o *SG2FQDNRule) FromModel(m sgm.FQDNRule) error {
	o.NdpiProtocols = []string{} //lint:nolint
	m.NdpiProtocols.Iterate(func(k dict.StringCiKey) bool {
		o.NdpiProtocols = append(o.NdpiProtocols, string(k))
		return true
	})
	o.SgFrom = m.ID.SgFrom
	o.FqndTo = FQDN(m.ID.FqdnTo.String())
	if err := o.Proto.FromModel(m.ID.Transport); err != nil {
		return err
	}
	if err := o.Ports.FromModel(m.Ports); err != nil {
		return err
	}
	o.Logs = m.Logs
	o.Action = ChainDefaultAction(strings.ToUpper(m.Action.String()))
	return nil
}

// ToModel -
func (o ICMP) ToModel() (ret sgm.ICMP, err error) {
	switch o.IPv {
	case pgIPv4:
		ret.IPv = 4
	case pgIPv6:
		ret.IPv = 6
	default:
		return ret, errors.Errorf("got unknown IP family (%v) from PG", o.IPv)
	}
	for _, n := range o.Tytes {
		if n < 0 || n > math.MaxUint8 {
			return ret, errors.Errorf("got ICMP out of range [0-255] message type (%v) from PG", n)
		}
		ret.Types.Put(uint8(n))
	}
	return ret, err
}

func ipFamilyFromModel(ipv uint8) (ret IpFamily, err error) {
	switch ipv {
	case sgm.IPv4:
		ret = pgIPv4
	case sgm.IPv6:
		ret = pgIPv6
	default:
		err = errors.Errorf("cannot convert (%v) IP family", ipv)
	}
	return ret, err
}

// FromModel -
func (o *ICMP) FromModel(m sgm.ICMP) error {
	var e error
	if o.IPv, e = ipFamilyFromModel(m.IPv); e != nil {
		return e
	}
	o.Tytes = IcmpTypes{}
	m.Types.Iterate(func(v uint8) bool {
		o.Tytes = append(o.Tytes, int16(v))
		return true
	})
	return nil
}

// ToModel -
func (o SgIcmpRule) ToModel() (ret sgm.SgIcmpRule, err error) {
	ret.Sg = o.Sg
	ret.Logs = o.Logs
	ret.Trace = o.Trace
	if err = ret.Action.FromString(string(o.Action)); err != nil {
		return ret, err
	}
	ret.Icmp, err = o.ICMP.ToModel()
	return ret, err
}

// FromModel -
func (o *SgIcmpRule) FromModel(m sgm.SgIcmpRule) error {
	o.Sg = m.Sg
	o.Logs = m.Logs
	o.Trace = m.Trace
	o.Action = ChainDefaultAction(strings.ToUpper(m.Action.String()))
	return o.ICMP.FromModel(m.Icmp)
}

// ToModel -
func (o SgSgIcmpRule) ToModel() (ret sgm.SgSgIcmpRule, err error) {
	ret.SgFrom = o.SgFrom
	ret.SgTo = o.SgTo
	ret.Logs = o.Logs
	ret.Trace = o.Trace
	if err = ret.Action.FromString(string(o.Action)); err != nil {
		return ret, err
	}
	ret.Icmp, err = o.ICMP.ToModel()
	return ret, err
}

// FromModel -
func (o *SgSgIcmpRule) FromModel(m sgm.SgSgIcmpRule) error {
	o.SgFrom = m.SgFrom
	o.SgTo = m.SgTo
	o.Logs = m.Logs
	o.Trace = m.Trace
	o.Action = ChainDefaultAction(strings.ToUpper(m.Action.String()))
	return o.ICMP.FromModel(m.Icmp)
}

// ToModel -
func (o IESgSgIcmpRule) ToModel() (ret sgm.IESgSgIcmpRule, err error) {
	ret.SgLocal = o.SgLocal
	ret.Sg = o.Sg
	ret.Logs = o.Logs
	ret.Trace = o.Trace
	if err = ret.Action.FromString(string(o.Action)); err != nil {
		return ret, err
	}
	if ret.Traffic, err = o.Traffic.ToModel(); err != nil {
		return ret, err
	}
	ret.Icmp, err = o.ICMP.ToModel()
	return ret, err
}

// FromModel -
func (o *IESgSgIcmpRule) FromModel(m sgm.IESgSgIcmpRule) error {
	o.SgLocal = m.SgLocal
	o.Sg = m.Sg
	o.Logs = m.Logs
	o.Trace = m.Trace
	o.Action = ChainDefaultAction(strings.ToUpper(m.Action.String()))
	if err := o.Traffic.FromModel(m.Traffic); err != nil {
		return err
	}
	return o.ICMP.FromModel(m.Icmp)
}

// FromModel -
func (o *Traffic) FromModel(m sgm.Traffic) error {
	var e error
	switch m {
	case sgm.INGRESS:
		*o = pgIngress
	case sgm.EGRESS:
		*o = pgEgress
	default:
		e = errors.Errorf("PG cannot adopt unknown 'traffic' '%s'(%v)", m, m)
	}
	return e
}

// ToModel -
func (o Traffic) ToModel() (ret sgm.Traffic, err error) {
	switch string(o) {
	case pgIngress:
		return sgm.INGRESS, nil
	case pgEgress:
		return sgm.EGRESS, nil
	}
	return 0, errors.Errorf("unsupported 'traffic' value (%s) come from PG", o)
}

// FromModel -
func (o *CidrSgRule) FromModel(m sgm.CidrSgRule) error { //nolint:dupl
	if err := o.Proto.FromModel(m.ID.Transport); err != nil {
		return err
	}
	o.CIDR = m.ID.CIDR
	o.SG = m.ID.SG
	o.Action = ChainDefaultAction(strings.ToUpper(m.Action.String()))
	if err := o.Traffic.FromModel(m.ID.Traffic); err != nil {
		return err
	}
	if err := o.Ports.FromModel(m.Ports); err != nil {
		return err
	}
	o.Logs = m.Logs
	o.Trace = m.Trace
	return nil
}

// ToModel -
func (o CidrSgRule) ToModel() (ret sgm.CidrSgRule, err error) {
	if ret.ID.Transport, err = o.Proto.ToModel(); err != nil {
		return ret, err
	}
	ret.ID.SG = o.SG
	ret.ID.CIDR = o.CIDR
	if err = ret.Action.FromString(string(o.Action)); err != nil {
		return ret, err
	}
	if ret.ID.Traffic, err = o.Traffic.ToModel(); err != nil {
		return ret, err
	}
	if ret.Ports, err = o.Ports.ToModel(); err != nil {
		return ret, err
	}
	ret.Logs = o.Logs
	ret.Trace = o.Trace
	return ret, nil
}

// FromModel -
func (o *CidrSgIcmpRule) FromModel(m sgm.CidrSgIcmpRule) error {
	o.CIDR = m.CIDR
	o.SG = m.SG
	o.Logs = m.Logs
	o.Trace = m.Trace
	o.Action = ChainDefaultAction(strings.ToUpper(m.Action.String()))
	if err := o.Traffic.FromModel(m.Traffic); err != nil {
		return err
	}
	return o.ICMP.FromModel(m.Icmp)
}

// ToModel -
func (o CidrSgIcmpRule) ToModel() (ret sgm.CidrSgIcmpRule, err error) {
	ret.CIDR = o.CIDR
	ret.SG = o.SG
	ret.Logs = o.Logs
	ret.Trace = o.Trace
	if err = ret.Action.FromString(string(o.Action)); err != nil {
		return ret, err
	}
	if ret.Traffic, err = o.Traffic.ToModel(); err != nil {
		return ret, err
	}
	ret.Icmp, err = o.ICMP.ToModel()
	return ret, err
}

// FromModel -
func (o *SgSgRule) FromModel(m sgm.SgSgRule) error { //nolint:dupl
	if err := o.Proto.FromModel(m.ID.Transport); err != nil {
		return err
	}
	o.SgLocal = m.ID.SgLocal
	o.Sg = m.ID.Sg
	o.Action = ChainDefaultAction(strings.ToUpper(m.Action.String()))
	if err := o.Traffic.FromModel(m.ID.Traffic); err != nil {
		return err
	}
	if err := o.Ports.FromModel(m.Ports); err != nil {
		return err
	}
	o.Logs = m.Logs
	o.Trace = m.Trace
	return nil
}

// ToModel -
func (o SgSgRule) ToModel() (ret sgm.SgSgRule, err error) {
	if ret.ID.Transport, err = o.Proto.ToModel(); err != nil {
		return ret, err
	}
	ret.ID.SgLocal = o.SgLocal
	ret.ID.Sg = o.Sg
	if err = ret.Action.FromString(string(o.Action)); err != nil {
		return ret, err
	}
	if ret.ID.Traffic, err = o.Traffic.ToModel(); err != nil {
		return ret, err
	}
	if ret.Ports, err = o.Ports.ToModel(); err != nil {
		return ret, err
	}
	ret.Logs = o.Logs
	ret.Trace = o.Trace
	return ret, err
}

const (
	pgIPv4 = "IPv4"
	pgIPv6 = "IPv6"
)

const (
	pgIngress = "ingress"
	pgEgress  = "egress"
)

var (
	modelProto2proto = map[sgm.NetworkTransport]string{
		sgm.TCP: strings.ToLower(sgm.TCP.String()),
		sgm.UDP: strings.ToLower(sgm.UDP.String()),
	}
	proto2modelProto = map[string]sgm.NetworkTransport{
		strings.ToLower(sgm.TCP.String()): sgm.TCP,
		strings.ToLower(sgm.UDP.String()): sgm.UDP,
	}
)
