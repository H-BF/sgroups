package sgroups

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_SGRuleIdentityFromString(t *testing.T) {
	cases := []struct {
		src     string
		exp     string
		expFail bool
	}{
		{` udp: 'sg0-/\+=' - 'sg0-/\+=' `, `udp:'sg0-/\+='-'sg0-/\+='`, false},
		{` uDp  : 'sg0-/\+=' - 'sg1' `, `udp:'sg0-/\+='-'sg1'`, false},
		{` tcp : 'sg0-/\+=' - 'sg1' `, `tcp:'sg0-/\+='-'sg1'`, false},
		{` tcP : 'sg0-/\+=' - 'sg1' `, `tcp:'sg0-/\+='-'sg1'`, false},
		{` uDpp : 'sg0-/\+=' - 'sg1' `, ``, true},
		{` udp : 'a sg0-/\+=' - 'sg1' `, ``, true},
		{` udp : 'sg0-/\+=' - 'b sg1' `, ``, true},
		{` udp : 'sg0-/\+=' - 'sg1 ' `, ``, true},
	}
	for i := range cases {
		c := cases[i]
		var obj SGRuleIdentity
		err := obj.FromString(c.src)
		if c.expFail {
			require.Errorf(t, err, "#case=%v", i)
		} else {
			actual := obj.String()
			require.Equalf(t, c.exp, actual, "#case=%v", i)
		}
	}
}
