package sgroups

import (
	"bytes"
	"crypto/md5"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"unsafe"

	"github.com/H-BF/corlib/pkg/ranges"
	"go.uber.org/multierr"
)

type PortSource string

type portSourceHelper struct{}

// IsValid check string of port range is valid
func (ps PortSource) IsValid() bool {
	for _, s := range strings.Split(string(ps), ",") {
		m := parsePortsRE.FindStringSubmatch(s)
		if !(len(m) != 0 && m[0] == s) {
			return false
		}
	}
	return true
}

// IsEq -
func (ps PortSource) IsEq(other PortSource) bool {
	var h portSourceHelper
	var rr1, rr2 []PortRange
	var e error
	if rr1, e = h.str2portranges(string(ps), ","); e != nil {
		return false
	}
	if rr2, e = h.str2portranges(string(other), ","); e != nil {
		return false
	}
	pr := NewPortRarnges()
	pr.Update(ranges.CombineExclude, append(rr1, rr2...)...)
	return pr.Len() == 0
}

// FromPortRange inits from PortRange
func (ps *PortSource) FromPortRange(r PortRange) error {
	buf := bytes.NewBuffer(nil)
	if e := (portSourceHelper{}).fromPortRange(r, buf); e != nil {
		return e
	}
	*ps = PortSource(buf.String())
	return nil
}

// FromPortRanges -
func (ps *PortSource) FromPortRanges(rr PortRanges) error {
	buf := bytes.NewBuffer(nil)
	var e error
	rr.Iterate(func(r PortRange) bool {
		if r.IsNull() {
			return true
		}
		if buf.Len() > 0 {
			_ = buf.WriteByte(',')
		}
		e = portSourceHelper{}.fromPortRange(r, buf)
		return e == nil
	})
	if e == nil {
		*ps = PortSource(buf.String())
	}
	return e
}

// ToPortRange string to port range
func (ps PortSource) ToPortRange() (PortRange, error) {
	ret, e := portSourceHelper{}.str2portrange(string(ps))
	if e == nil && ret != nil && ret.IsNull() {
		ret = nil
	}
	return ret, e
}

// ToPortRanges -
func (ps PortSource) ToPortRanges() (PortRanges, error) {
	ret := NewPortRarnges()
	src, err := portSourceHelper{}.str2portranges(string(ps), ",")
	if err != nil {
		return ret, err
	}
	ret.Update(ranges.CombineMerge, src...)
	return ret, nil
}

func (h portSourceHelper) str2portranges(ps string, sep string) ([]PortRange, error) {
	if sep == "" {
		panic("invalid separator")
	}
	var ret []PortRange
	for _, s := range strings.Split(ps, sep) {
		r, e := h.str2portrange(s)
		if e != nil {
			return nil, e
		}
		if r != nil && !r.IsNull() {
			ret = append(ret, r)
		}
	}
	return ret, nil
}

func (portSourceHelper) str2portrange(ps string) (PortRange, error) {
	var (
		err  error
		l, r uint64
	)
	m := parsePortsRE.FindStringSubmatch(ps)
	if len(m) != 4 { //nolint:gomnd
		return nil, errIncorrectPortsSource
	}
	if m[2] != "" && m[3] != "" {
		l, err = strconv.ParseUint(m[2], 10, 16)
		if err == nil {
			r, err = strconv.ParseUint(m[3], 10, 16)
		}
	} else if m[1] != "" {
		l, err = strconv.ParseUint(m[1], 10, 16)
		r = l
	} else {
		return nil, nil
	}
	if err != nil {
		return nil, multierr.Combine(errIncorrectPortsSource, err)
	}
	return PortRangeFactory.Range(
		PortNumber(l), false,
		PortNumber(r), false,
	), nil
}

func (portSourceHelper) fromPortRange(r PortRange, w io.Writer) error {
	if r == nil || r.IsNull() {
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
		fmt.Fprintf(w, "%v", vl)
	} else {
		fmt.Fprintf(w, "%v-%v", vl, vr)
	}
	return nil
}

func makeSlice[T any](args ...T) []T {
	return args
}

func packPortRanges(pr PortRanges, w io.Writer) {
	var bounds [2]struct {
		v  PortNumber
		ex bool
	}
	sl := unsafe.Slice((*byte)(unsafe.Pointer(&bounds)), unsafe.Sizeof(bounds))
	pr.Iterate(func(r PortRange) bool {
		for i, b := range makeSlice(r.Normalize().Bounds()) {
			bounds[i].v, bounds[i].ex = b.GetValue()
		}
		_, _ = w.Write(sl)
		return true
	})
}

func packSGRulePorts(pr SGRulePorts, w io.Writer) {
	for _, item := range makeSlice(pr.S, pr.D) {
		packPortRanges(item, w)
		_, _ = w.Write([]byte{'|'})
	}
}

// AreRulePortsEq -
func AreRulePortsEq(l, r []SGRulePorts) bool {
	if len(l) != len(r) {
		return false
	}
	type key = [md5.Size]byte
	type dict = map[key]int
	ld := make(dict, len(l))
	rd := make(dict, len(r))
	dst := makeSlice(&ld, &rd)
	buf := bytes.NewBuffer(nil)
	for i, item := range makeSlice(l, r) {
		d := *dst[i]
		for _, pr := range item {
			buf.Reset()
			packSGRulePorts(pr, buf)
			d[md5.Sum(buf.Bytes())]++
		}
	}
	if len(ld) != len(rd) {
		return false
	}
	for k, v := range ld {
		if v != rd[k] {
			return false
		}
	}
	return true
}

var (
	errIncorrectPortsSource = fmt.Errorf("incorrect port range(s) source")
	parsePortsRE            = regexp.MustCompile(`^\s*((?:(\d+)\s*-\s*(\d+))|\d+|\s*)\s*$`)
)
