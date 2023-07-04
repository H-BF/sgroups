package sgroups

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_PortSourceValid(t *testing.T) {
	require.True(t, PortSource("   ").IsValid())
	require.True(t, PortSource("  ,  ").IsValid())
	require.True(t, PortSource("  12 ").IsValid())
	require.True(t, PortSource("  12, 10, ").IsValid())
	require.True(t, PortSource("  12 - 13 ").IsValid())
	require.False(t, PortSource("   - 13 ").IsValid())
	require.True(t, PortSource("   ").IsValid())
	require.False(t, PortSource(" 12  -  ").IsValid())
	require.True(t, PortSource("").IsValid())
	require.False(t, PortSource(" a ").IsValid())
	require.False(t, PortSource(" a 10 ").IsValid())
	require.False(t, PortSource("  10 -- 13 ").IsValid())
}

func Test_PortSource2PortRange(t *testing.T) {
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
		{" 11 - 10  ", nil, false},
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

func Test_PortSourceEq(t *testing.T) {
	cases := []struct {
		S1, S2 PortSource
		expEq  bool
	}{
		{"", " ", true},
		{"", ", , ,   ", true},
		{"10", ", , ,   ", false},
		{"10", "10", true},
		{"11, 12, 10-20", "10-20, 11", true},
		{"11, 22, 10-20", "10-20, 11", false},
	}
	for i := range cases {
		c := cases[i]
		val := c.S1.IsEq(c.S2)
		require.Equalf(t, c.expEq, val, "%v)  '%s' .EQ. '%s'", i, c.S1, c.S2)
	}
}

func Test_AreRulePortsEq(t *testing.T) {
	rp := func(s, d PortSource) SGRulePorts {
		var ret SGRulePorts
		var e error
		ret.S, e = s.ToPortRanges()
		require.NoError(t, e)
		ret.D, e = d.ToPortRanges()
		require.NoError(t, e)
		return ret
	}
	cases := []struct {
		l, r  []SGRulePorts
		expEq bool
	}{
		{makeSlice(rp("1", "1 ")), makeSlice(rp("1", "1")), true},
		{makeSlice(rp("1", "1"), rp("1", "1")), makeSlice(rp("1", "1")), false},
		{makeSlice(rp("1", "1"), rp("1", "1")), makeSlice(rp("1", "1"), rp("1", "1")), true},
		{makeSlice(rp("1", "1"), rp("1", "1")), makeSlice(rp("1", "1"), rp("1", "2")), false},
		{makeSlice(rp("1, 10-20", "1 ")), makeSlice(rp("10-20, 1", "1")), true},
		{makeSlice(rp("1", "1"), rp("2", "2")), makeSlice(rp("2", "2"), rp("1", "1")), true},
		{makeSlice(rp("1", "1"), rp("2", "2")), makeSlice(rp("2", "2"), rp("1", "1"), rp("3", "3")), false},
		{makeSlice(rp("3", "3"), rp("1", "1"), rp("2", "2")), makeSlice(rp("2", "2"), rp("1", "1")), false},
	}
	for i := range cases {
		c := cases[i]
		val := AreRulePortsEq(c.l, c.r)
		require.Equalf(t, c.expEq, val, "%v)", i)
	}
}
