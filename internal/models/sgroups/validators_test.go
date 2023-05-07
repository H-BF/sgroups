package sgroups

import (
	"bytes"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidate_NetworkTransport(t *testing.T) {
	cases := []struct {
		x    NetworkTransport
		fail bool
	}{
		{TCP, false},
		{UDP, false},
		{NetworkTransport(100), true},
	}
	for i := range cases {
		c := cases[i]
		e := c.x.Validate()
		if !c.fail {
			require.NoErrorf(t, e, "test case #%v", i)
		} else {
			require.Errorf(t, e, "test case #%v", i)
		}
	}
}

func TestValidate_Network(t *testing.T) {
	nnw := func(s string) net.IPNet {
		_, ret, e := net.ParseCIDR(s)
		require.NoError(t, e)
		return *ret
	}
	type item = struct {
		nw   Network
		fail bool
	}
	cases := []item{
		{Network{nnw("10.10.10.10/32"), "name"}, false},
		{Network{nnw("10.10.10.10/0"), "name"}, false},
		{Network{nnw("2001:db8:3333:4444:5555:6666:7777:8888/0"), "name"}, false},
		{Network{nnw("2001:db8:3333:4444:5555:6666:7777:8888/128"), "name"}, false},
		{Network{nnw("2001:db8:3333:4444:5555:6666:7777:8888/128"), ""}, true},
	}
	badNW := Network{Name: "name"}
	badNW.Net.IP = bytes.Repeat([]byte{255}, 40)
	cases = append(cases, item{badNW, true})
	for i := range cases {
		c := cases[i]
		e := c.nw.Validate()
		if !c.fail {
			require.NoErrorf(t, e, "test case #%v", i)
		} else {
			require.Errorf(t, e, "test case #%v", i)
		}
	}
}

func TestValidate_SecurityGroup(t *testing.T) {
	type item = struct {
		sg   SecurityGroup
		fail bool
	}
	cases := []item{
		{SecurityGroup{}, true},
		{SecurityGroup{Name: "sg"}, false},
		{SecurityGroup{Name: "sg", Networks: []string{""}}, true},
		{SecurityGroup{Name: "sg", Networks: []string{"nw"}}, false},
		{SecurityGroup{Name: "sg", Networks: []string{"nw", "nw"}}, true},
	}
	for i := range cases {
		c := cases[i]
		e := c.sg.Validate()
		if !c.fail {
			require.NoErrorf(t, e, "test case #%v", i)
		} else {
			require.Errorf(t, e, "test case #%v", i)
		}
	}
}

func TestValidate_SGRuleIdentity(t *testing.T) {
	sg := func(n string, nws ...string) SecurityGroup {
		return SecurityGroup{
			Name:     n,
			Networks: nws,
		}
	}
	type item = struct {
		id   SGRuleIdentity
		fail bool
	}
	cases := []item{
		{SGRuleIdentity{}, true},
		{SGRuleIdentity{SgFrom: sg("n1"), Transport: TCP}, true},
		{SGRuleIdentity{SgTo: sg("n2"), Transport: TCP}, true},
		{SGRuleIdentity{SgFrom: sg("n1"), SgTo: sg("n2"), Transport: TCP}, false},
		{SGRuleIdentity{SgFrom: sg("n1"), SgTo: sg("n2"), Transport: UDP}, false},
		{SGRuleIdentity{SgFrom: sg("n1"), SgTo: sg("n2"), Transport: NetworkTransport(100)}, true},
		{SGRuleIdentity{SgFrom: sg("n1", ""), SgTo: sg("n2", ""), Transport: UDP}, false},
	}
	for i := range cases {
		c := cases[i]
		e := c.id.Validate()
		if c.fail {
			require.Errorf(t, e, "test case #%v", i)
		} else {
			require.NoErrorf(t, e, "test case #%v", i)
		}
	}
}

func TestValidate_SGRulePorts(t *testing.T) {
	pr := func(s string) PortRange {
		ret, e := PortSource(s).ToPortRange()
		require.NoError(t, e)
		return ret
	}
	type item = struct {
		ports SGRulePorts
		fail  bool
	}
	cases := []item{
		{SGRulePorts{}, true},
		{SGRulePorts{S: pr("10")}, false},
		{SGRulePorts{D: pr("10")}, false},
		{SGRulePorts{S: pr("10"), D: pr("10")}, false},
		{SGRulePorts{S: pr("10"), D: pr("")}, false},
	}
	for i := range cases {
		c := cases[i]
		e := c.ports.Validate()
		if !c.fail {
			require.NoErrorf(t, e, "test case #%v", i)
		} else {
			require.Errorf(t, e, "test case #%v", i)
		}
	}
}

func TestValidate_arraySGRulePorts(t *testing.T) {
	pr := func(s, d string) SGRulePorts {
		p1, e1 := PortSource(s).ToPortRange()
		require.NoError(t, e1)
		p2, e2 := PortSource(d).ToPortRange()
		require.NoError(t, e2)
		return SGRulePorts{S: p1, D: p2}
	}
	type pp = []SGRulePorts
	type item = struct {
		ports pp
		fail  bool
	}
	cases := []item{
		{pp{}, false},
		{pp{pr("", "10")}, false},
		{pp{pr("10", "10"), pr("20", "20")}, false},
		{pp{pr("", "10"), pr("20", "20")}, true},
		{pp{pr("10-20", "10"), pr("20", "20")}, true},
		{pp{pr("10-20", "10"), pr("10", "20")}, true},
		{pp{pr("10-20", "10"), pr("9", "20")}, false},
		{pp{pr("10-20", "10"), pr("21", "20")}, false},
	}
	for i := range cases {
		c := cases[i]
		e := arraySGRulePorts(c.ports).Validate()
		if !c.fail {
			require.NoErrorf(t, e, "test case #%v", i)
		} else {
			require.Errorf(t, e, "test case #%v", i)
		}
	}
}

func TestValidate_SGRule(t *testing.T) {
	rp := func(s, d string) SGRulePorts {
		p1, e1 := PortSource(s).ToPortRange()
		require.NoError(t, e1)
		p2, e2 := PortSource(d).ToPortRange()
		require.NoError(t, e2)
		return SGRulePorts{S: p1, D: p2}
	}
	sg := func(n string, nws ...string) SecurityGroup {
		return SecurityGroup{
			Name:     n,
			Networks: nws,
		}
	}
	r := func(sg1, sg2 SecurityGroup, tr NetworkTransport, ports ...SGRulePorts) SGRule {
		return SGRule{
			SGRuleIdentity: SGRuleIdentity{
				SgTo:      sg2,
				SgFrom:    sg1,
				Transport: tr,
			},
			Ports: ports,
		}
	}
	type item = struct {
		rule SGRule
		fail bool
	}
	cases := []item{
		{r(sg("sg1"), sg("sg2"), TCP), false},
		{r(sg("sg1", ""), sg("sg2"), TCP, rp("10", "10")), false},
		{r(sg("", ""), sg("sg2", ""), TCP, rp("10", "10")), true},
		{r(sg("sg1"), sg(""), TCP, rp("10", "10")), true},
		{r(sg("sg1"), sg("sg1"), TCP, rp("10", "10")), false},
		{r(sg("sg1"), sg("sg1"), TCP, rp("10", "")), false},
		{r(sg("sg1"), sg("sg1"), TCP, rp("", "10")), false},
		{r(sg("sg1"), sg("sg1"), TCP, rp("", "10"), rp("1", "10")), true},
		{r(sg("sg1"), sg("sg1"), TCP, rp("10", "10"), rp("9-10", "10")), true},
		{r(sg("sg1"), sg("sg1"), TCP, rp("10", "10"), rp("11", "10")), false},
	}
	for i := range cases {
		c := cases[i]
		e := c.rule.Validate()
		if !c.fail {
			require.NoErrorf(t, e, "test case #%v", i)
		} else {
			require.Errorf(t, e, "test case #%v", i)
		}
	}
}
