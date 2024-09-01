package sgroups

import (
	"bytes"
	"net"
	"testing"

	"github.com/H-BF/corlib/pkg/dict"
	"github.com/stretchr/testify/require"
)

func TestValidate_Traffic(t *testing.T) {
	cases := []struct {
		x    Traffic
		fail bool
	}{
		{INGRESS, false},
		{EGRESS, false},
		{Traffic(100), true},
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
		{Network{nnw("10.10.10.10/32"), "n"}, false},
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
	nws := func(names ...NetworkName) (ret dict.HSet[NetworkName]) {
		ret.PutMany(names...)
		return ret
	}
	cases := []item{
		{SecurityGroup{}, true},
		{SecurityGroup{Name: "sg", DefaultAction: DROP + 100}, true},
		{SecurityGroup{Name: "sg", DefaultAction: ACCEPT + 100}, true},
		{SecurityGroup{Name: "sg", DefaultAction: ACCEPT}, false},
		{SecurityGroup{Name: "sg", DefaultAction: DROP}, false},
		{SecurityGroup{Name: "sg", Networks: nws("")}, true},
		{SecurityGroup{Name: "sg", Networks: nws("nw")}, false},
		{SecurityGroup{Name: "sg", Networks: nws("nw", "nw")}, false},
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
	type item = struct {
		id   SGRuleIdentity
		fail bool
	}
	cases := []item{
		{SGRuleIdentity{}, true},
		{SGRuleIdentity{SgFrom: "n1", Transport: TCP}, true},
		{SGRuleIdentity{SgTo: "n2", Transport: TCP}, true},
		{SGRuleIdentity{SgFrom: "n1", SgTo: "n2", Transport: TCP + 100}, true},
		{SGRuleIdentity{SgFrom: "n1", SgTo: "n2", Transport: UDP + 100}, true},
		{SGRuleIdentity{SgFrom: "n1", SgTo: "n2", Transport: TCP}, false},
		{SGRuleIdentity{SgFrom: "n1", SgTo: "n2", Transport: UDP}, false},
		{SGRuleIdentity{SgFrom: "n1", SgTo: "n2", Transport: NetworkTransport(100)}, true},
		{SGRuleIdentity{SgFrom: "n1", SgTo: "n2", Transport: UDP}, false},
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
	pr := func(s string) PortRanges {
		ret, e := PortSource(s).ToPortRanges()
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
		{SGRulePorts{S: pr(""), D: pr("10")}, false},
		{SGRulePorts{S: pr(""), D: pr("")}, true},
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

func TestValidate_SGRule(t *testing.T) {
	rp := func(s, d string) SGRulePorts {
		p1, e1 := PortSource(s).ToPortRanges()
		require.NoError(t, e1)
		p2, e2 := PortSource(d).ToPortRanges()
		require.NoError(t, e2)
		return SGRulePorts{S: p1, D: p2}
	}
	sg := func(n string, nws ...string) SecurityGroup {
		var nw dict.HSet[NetworkName]
		nw.PutMany(nws...)
		return SecurityGroup{
			Name:     n,
			Networks: nw,
		}
	}
	r := func(sg1, sg2 SecurityGroup, tr NetworkTransport, ports ...SGRulePorts) SGRule {
		return SGRule{
			ID: SGRuleIdentity{
				SgTo:      sg2.Name,
				SgFrom:    sg1.Name,
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
		{r(sg("sg1", ""), sg("sg2"), TCP, rp("", "")), true},
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

func Test_Validate_SgIcmpRule(t *testing.T) {
	var r SgIcmpRule
	e := r.Validate()
	require.Error(t, e)
	r.Sg = "/123/"
	r.Icmp.IPv = 6
	r.Icmp.Types.Put(1)
	e = r.Validate()
	require.NoError(t, e)
}

func Test_Validate_IECidrSgIcmpRule(t *testing.T) {
	cases := []struct {
		cidr string
		ipv  uint8
		fail bool
	}{
		{"1.1.1.1/24", IPv4, false},
		{"2001:db8::/64", IPv6, false},
		{"1.1.1.1/24", IPv6, true},
		{"2001:db8::/64", IPv4, true},
	}
	for i := range cases {
		c := cases[i]
		_, cidr, err := net.ParseCIDR(c.cidr)
		require.NoError(t, err)
		rule := IECidrSgIcmpRule{INGRESS, *cidr, "sg1", ICMP{IPv: uint8(c.ipv)}, false, false, RA_DROP, RulePriority{}}
		e := rule.Validate()
		if !c.fail {
			require.NoErrorf(t, e, "test case #%v failed", i)
		} else {
			require.Errorf(t, e, "test case #%v failed", i)
		}
	}
}
