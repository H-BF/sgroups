package pg

import (
	"strings"

	sgm "github.com/H-BF/sgroups/internal/models/sgroups"

	"github.com/H-BF/corlib/pkg/ranges"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/pkg/errors"
)

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
	ret.SgFrom.Name = o.SgFrom
	ret.SgTo.Name = o.SgTo
	if ret.Transport, err = o.Proto.ToModel(); err != nil {
		return ret, err
	}
	ret.Ports, err = o.Ports.ToModel()
	return ret, err
}

// FromModel -
func (o *SGRule) FromModel(m sgm.SGRule) error {
	o.SgFrom = m.SgFrom.Name
	o.SgTo = m.SgTo.Name
	if err := o.Proto.FromModel(m.Transport); err != nil {
		return err
	}
	if err := o.Ports.FromModel(m.Ports); err != nil {
		return err
	}
	return nil
}

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
