package sgroups

import (
	"fmt"
	"regexp"
	"strconv"

	"github.com/H-BF/corlib/pkg/ranges"
	"go.uber.org/multierr"
)

type PortSource string

// IsValid check string of port range is valid
func (ps PortSource) IsValid() bool {
	if ps.isEmpry() {
		return true
	}
	n := len(parsePortsRE.FindStringSubmatch(string(ps)))
	return n == 4 //nolint:gomnd
}

// FromPortRange inits from PortRange
func (ps *PortSource) FromPortRange(r PortRange) error {
	if r == nil || r.IsNull() {
		*ps = ""
		return nil
	}
	lb, rb := r.Bounds()
	if _, excl := lb.GetValue(); excl {
		lb = rb.AsIncluded()
		if _, excl = lb.GetValue(); excl {
			return errIncorrectPortsSource
		}
	}
	if _, excl := rb.GetValue(); excl {
		rb = rb.AsIncluded()
		if _, excl = rb.GetValue(); excl {
			return errIncorrectPortsSource
		}
	}
	vr, _ := rb.GetValue()
	vl, _ := lb.GetValue()
	if vl == vr {
		*ps = PortSource(fmt.Sprintf("%v", vl))
	} else {
		*ps = PortSource(fmt.Sprintf("%v-%v", vl, vr))
	}
	return nil
}

// ToPortRange string to port range
func (ps PortSource) ToPortRange() (PortRange, error) {
	var (
		ret  PortRange
		err  error
		l, r uint64
	)
	m := parsePortsRE.FindStringSubmatch(string(ps))
	if len(m) != 4 { //nolint:gomnd
		if ps.isEmpry() {
			return nil, nil
		}
		return ret, errIncorrectPortsSource
	}
	if len(m[2])*len(m[3]) != 0 {
		l, err = strconv.ParseUint(m[2], 10, 16)
		if err == nil {
			r, err = strconv.ParseUint(m[3], 10, 16)
		}
	} else {
		l, err = strconv.ParseUint(m[1], 10, 16)
		r = l
	}
	if err != nil {
		return ret, multierr.Combine(errIncorrectPortsSource, err)
	}
	if PortNumber(r) < PortNumber(l) {
		return ret, errIncorrectPortsSource
	}
	ret = PortRangeFactory.Range(PortNumber(l), false, PortNumber(r), false)
	return ret, err
}

func (ps PortSource) isEmpry() bool {
	for _, c := range ps {
		if c != ' ' {
			return false
		}
	}
	return true
}

// ArePortMultiRangesEq checks if two multi ranges are equal
func ArePortMultiRangesEq(l, r PortRanges) bool {
	n := l.Len()
	if n != r.Len() {
		return false
	}
	rr := make([]PortRange, 0, 2*n)
	l.Iterate(func(r PortRange) bool {
		rr = append(rr, r)
		return true
	})
	r.Iterate(func(r PortRange) bool {
		rr = append(rr, r)
		return true
	})
	x := ranges.NewMultiRange(PortRangeFactory)
	x.Update(ranges.CombineExclude, rr...)
	return x.Len() == 0
}

// AreRulePortsEq -
func AreRulePortsEq(l, r []SGRulePorts) bool {
	if len(l) != len(r) {
		return false
	}
	a := make(map[PortSource]PortSource, len(l))
	for _, p := range l {
		var s, d PortSource
		e := s.FromPortRange(p.S)
		if e == nil {
			e = d.FromPortRange(p.D)
		}
		if e != nil {
			return false
		}
		a[s] = d
	}
	for _, p := range r {
		var s, d PortSource
		e := s.FromPortRange(p.S)
		if e == nil {
			e = d.FromPortRange(p.D)
		}
		if e != nil {
			return false
		}
		if v, ok := a[s]; ok && d == v {
			delete(a, s)
			continue
		}
		return false
	}
	return len(a) == 0
}

var (
	errIncorrectPortsSource = fmt.Errorf("incorrect port range(s) source")
	parsePortsRE            = regexp.MustCompile(`^\s*((?:(\d+)\s*-\s*(\d+))|\d+)\s*$`)
)
