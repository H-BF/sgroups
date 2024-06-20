package sgroups

import (
	"testing"

	model "github.com/H-BF/sgroups/internal/domains/sgroups"

	"github.com/stretchr/testify/require"
)

func Test_validateSecGroupsDataIn(t *testing.T) {
	type sgs = []model.SecurityGroup
	type tcase = struct {
		sgs
		expectFail bool
	}
	sg := func(sgName string, nws ...model.NetworkName) model.SecurityGroup {
		ret := model.SecurityGroup{Name: sgName}
		ret.Networks.PutMany(nws...)
		return ret
	}
	cases := []tcase{
		{sgs{sg("sg1")}, false},
		{sgs{sg("sg1"), sg("sg1", "nw1")}, false},
		{sgs{sg("sg1", "nw1", "nw2", "nw3"), sg("sg1", "nw1")}, false},
		{sgs{sg("sg1", "nw1"), sg("sg1", "nw1", "nw2", "nw3")}, false},
		{sgs{sg("sg1", "nw1"), sg("sg2", "nw1", "nw2", "nw3")}, true},
	}

	for i := range cases {
		c := cases[i]
		e := validateSecGroupsDataIn(c.sgs)
		check := require.Errorf
		if !c.expectFail {
			check = require.NoErrorf
		}
		check(t, e, "on test-case #%v", i)
	}
}
