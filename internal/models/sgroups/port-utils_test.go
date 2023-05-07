package sgroups

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_PortSourceValid(t *testing.T) {
	require.True(t, PortSource("  12 ").IsValid())
	require.True(t, PortSource("  12 - 13 ").IsValid())
	require.False(t, PortSource("   - 13 ").IsValid())
	require.True(t, PortSource("   ").IsValid())
	require.False(t, PortSource(" 12  -  ").IsValid())
	require.True(t, PortSource("").IsValid())
	require.False(t, PortSource(" a ").IsValid())
	require.False(t, PortSource(" a 10 ").IsValid())
	require.False(t, PortSource("  10 -- 13 ").IsValid())
}

func Test_PortSource(t *testing.T) {
	eq := func(a, b PortRange) bool {
		if a == nil && b == nil {
			return true
		}
		if (a == nil && b != nil) || (a != nil && b == nil) {
			return false
		}
		l0, r0 := a.Bounds()
		l1, r1 := a.Bounds()
		return l0.Cmp(l1)|r0.Cmp(r1) == 0
	}
	cases := []struct {
		s    string
		exp  PortRange
		fail bool
	}{
		{"", nil, false},
		{" ", nil, false},
		{" 10 ", PortRangeFactory.Range(10, false, 10, false), false},
		{" 10 - 10 ", PortRangeFactory.Range(10, false, 10, false), false},
		{" 10 - 11 ", PortRangeFactory.Range(10, false, 11, false), false},
		{" - 10 - 11 ", nil, true},
		{" 11 - 10  ", nil, true},
		{" 11 - 65536  ", nil, true},
	}
	for i := range cases {
		c := cases[i]
		r, e := PortSource(c.s).ToPortRange()
		if c.fail {
			require.Errorf(t, e, "%v# '%s'", i, c.s)
		} else {
			require.NoErrorf(t, e, "%v# '%s'", i, c.s)
			require.Truef(t, eq(r, c.exp), "%v# '%s'", i, c.s)
		}
	}
}

func mkRanges(ss ...string) []PortRange {
	var ret []PortRange
	for _, s := range ss {
		if len(strings.TrimSpace(s)) == 0 {
			ret = append(ret, PortRangeFull)
		} else {
			p, e := PortSource(s).ToPortRange()
			if e != nil {
				panic(e)
			}
			ret = append(ret, p)
		}
	}
	return ret
}
