package sgroups

import (
	"testing"

	"github.com/stretchr/testify/require"
)

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
		{args2slice(rp("1", "1 ")), args2slice(rp("1", "1")), true},
		{args2slice(rp("1", "1"), rp("1", "1")), args2slice(rp("1", "1")), false},
		{args2slice(rp("1", "1"), rp("1", "1")), args2slice(rp("1", "1"), rp("1", "1")), true},
		{args2slice(rp("1", "1"), rp("1", "1")), args2slice(rp("1", "1"), rp("1", "2")), false},
		{args2slice(rp("1, 10-20", "1 ")), args2slice(rp("10-20, 1", "1")), true},
		{args2slice(rp("1", "1"), rp("2", "2")), args2slice(rp("2", "2"), rp("1", "1")), true},
		{args2slice(rp("1", "1"), rp("2", "2")), args2slice(rp("2", "2"), rp("1", "1"), rp("3", "3")), false},
		{args2slice(rp("3", "3"), rp("1", "1"), rp("2", "2")), args2slice(rp("2", "2"), rp("1", "1")), false},
	}
	for i := range cases {
		c := cases[i]
		val := AreRulePortsEq(c.l, c.r)
		require.Equalf(t, c.expEq, val, "%v)", i)
	}
}
