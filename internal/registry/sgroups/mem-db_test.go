package sgroups

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/H-BF/sgroups/internal/dict"
	model "github.com/H-BF/sgroups/internal/models/sgroups"
	"github.com/stretchr/testify/suite"
)

func Test_MemDB(t *testing.T) {
	suite.Run(t, new(memDbSuite))
}

type memDbSuite struct {
	reg Registry
	db  MemDB
	suite.Suite
}

func (sui *memDbSuite) SetupTest() {
	sui.Require().Nil(sui.reg)
	db, err := NewMemDB(AllTables())
	sui.Require().NoError(err)
	sui.reg = NewRegistryFromMemDB(db)
	sui.db = db
}

func (sui *memDbSuite) TearDownTest() {
	if sui.reg != nil {
		e := sui.reg.Close()
		sui.Require().NoError(e)
		sui.reg = nil
		sui.db = nil
	}
}

func (sui *memDbSuite) regWriter() Writer {
	ctx := context.TODO()
	w, e := sui.reg.Writer(ctx)
	sui.Require().NoError(e)
	return w
}

func (sui *memDbSuite) regReader() Reader {
	ctx := context.TODO()
	r, e := sui.reg.Reader(ctx)
	sui.Require().NoError(e)
	return r
}

func (sui *memDbSuite) newIPNet(cidr string) net.IPNet {
	_, n, err := net.ParseCIDR(cidr)
	sui.Require().NoError(err)
	return *n
}

func (sui *memDbSuite) newNetwork(name string, cidr string) model.Network {
	sui.Require().NotEmpty(name)
	return model.Network{
		Name: name,
		Net:  sui.newIPNet(cidr),
	}
}

func (sui *memDbSuite) newSG(name string, nws ...model.Network) model.SecurityGroup {
	sui.Require().NotEmpty(name)
	ret := model.SecurityGroup{Name: name}
	for i := range nws {
		ret.Networks = append(ret.Networks, nws[i].Name)
	}
	return ret
}

func (sui *memDbSuite) newRulePorts(s, d model.PortSource) model.SGRulePorts {
	a, e1 := s.ToPortRanges()
	sui.Require().NoError(e1)
	b, e2 := d.ToPortRanges()
	sui.Require().NoError(e2)
	return model.SGRulePorts{S: a, D: b}
}

func (sui *memDbSuite) newSGRule(sgFrom, sgTo string, t model.NetworkTransport, ports ...model.SGRulePorts) model.SGRule {
	return model.SGRule{
		ID: model.SGRuleIdentity{
			Transport: t,
			SgFrom:    sgFrom,
			SgTo:      sgTo,
		},
		Ports:  ports,
		Action: model.ACCEPT,
	}
}

func (sui *memDbSuite) TestSGRuleIsEq() {
	r := func(from, to string, t model.NetworkTransport, ports ...model.SGRulePorts) model.SGRule {
		return model.SGRule{
			ID: model.SGRuleIdentity{
				SgFrom:    from,
				SgTo:      to,
				Transport: t,
			},
			Ports: ports,
		}
	}

	p := func(s, d model.PortSource) model.SGRulePorts {
		return sui.newRulePorts(s, d)
	}
	type item = struct {
		r1   model.SGRule
		r2   model.SGRule
		isEq bool
	}
	cases := []item{
		{r("a", "b", model.TCP), r("a", "b", model.TCP), true},
		{r("a", "b", model.TCP), r("a", "b", model.UDP), false},
		{r("a", "b", model.TCP), r("a", "b", model.TCP, p("10", "10")), false},
		{r("a", "b", model.TCP, p("10", "10")), r("a", "b", model.TCP), false},
		{r("a", "b", model.TCP, p("10", "10")), r("a", "b", model.TCP, p("10", "10")), true},
		{r("a", "b", model.TCP, p("10-10", "10")), r("a", "b", model.TCP, p("10-10", "10")), true},
		{r("a", "b", model.TCP, p("10-20", "10"), p("30-40", "10")),
			r("a", "b", model.TCP, p("30-40", "10"), p("10-20", "10")), true},
		{r("a", "b", model.TCP, p("10-20", "20"), p("30-40", "10")),
			r("a", "b", model.TCP, p("30-40", "20"), p("10-20", "10")), false},
	}
	for i := range cases {
		c := cases[i]
		eq := c.r1.IsEq(c.r2)
		sui.Require().Equalf(c.isEq, eq, "test case #%v", i)
	}
}

func (sui *memDbSuite) TestSyncStatus() {
	ctx := context.TODO()
	rd := sui.regReader()
	_, e := rd.GetSyncStatus(ctx)
	sui.Require().NoError(e)
	//sui.Require().Nil(v)
	x := syncStatus{
		ID: 1,
		SyncStatus: model.SyncStatus{
			UpdatedAt: time.Now(),
		},
	}

	wr := sui.db.Writer()
	e = wr.Upsert(TblSyncStatus, x)
	sui.Require().NoError(e)
	e = wr.Commit()
	sui.Require().NoError(e)

	rd = sui.regReader()
	var v *model.SyncStatus
	v, e = rd.GetSyncStatus(ctx)
	sui.Require().NoError(e)
	sui.Require().NotNil(v)
	sui.Require().Equal(x.UpdatedAt, v.UpdatedAt)
}

func (sui *memDbSuite) TestOverNW() {
	ctx := context.TODO()
	nws := []model.Network{ // overlapped
		sui.newNetwork("nwc", "10.100.0.101/32"),
		sui.newNetwork("nwd", "10.100.0.1/24"),
		//sui.newNetwork("nwd", "10.100.0.100/30"),
	}
	w := sui.regWriter()
	e := w.SyncNetworks(ctx, nws, NoScope)
	sui.Require().NoError(e)
	e = w.Commit()
	sui.Require().Error(e)
}

func (sui *memDbSuite) TestCheckNetworksOverlap() {
	ctx := context.TODO()
	nws := []model.Network{ //not overlappedd
		//sui.newNetwork("nwa", "10.100.0.10/32"),
		//sui.newNetwork("nwb", "10.100.0.10/31"),
		//sui.newNetwork("nwc", "10.100.0.10/30"),
		//sui.newNetwork("nwd", "10.100.0.10/24"),
		sui.newNetwork("nw1", "10.10.10.1/24"),
		sui.newNetwork("nw2", "10.10.11.2/24"),
		sui.newNetwork("nw3", "10.10.12.3/24"),
	}
	w := sui.regWriter()
	e := w.SyncNetworks(ctx, nws, NoScope)
	sui.Require().NoError(e)
	e = w.Commit()
	sui.Require().NoError(e)

	nws = []model.Network{ // overlapped
		sui.newNetwork("nwc", "10.100.0.0/32"),
		sui.newNetwork("nwd", "10.100.0.0/24"),
		sui.newNetwork("nw1", "10.10.11.19/32"),
		sui.newNetwork("nw2", "10.10.11.1/24"),
		sui.newNetwork("nw3", "10.10.12.1/24"),
	}
	w = sui.regWriter()
	e = w.SyncNetworks(ctx, nws, NoScope)
	sui.Require().NoError(e)
	e = w.Commit()
	sui.Require().Error(e)

	nws = []model.Network{ // not overlapped
		sui.newNetwork("nw1", "10.10.11.0/32"),
		sui.newNetwork("nw2", "10.10.11.1/32"),
	}
	w = sui.regWriter()
	e = w.SyncNetworks(ctx, nws, NoScope)
	sui.Require().NoError(e)
	e = w.Commit()
	sui.Require().NoError(e)

	nws = []model.Network{ // overlapped
		sui.newNetwork("nw1", "10.10.11.1/31"),
		sui.newNetwork("nw2", "10.10.11.1/32"),
	}
	w = sui.regWriter()
	e = w.SyncNetworks(ctx, nws, NoScope)
	sui.Require().NoError(e)
	e = w.Commit()
	sui.Require().Error(e)
}

func (sui *memDbSuite) TestSyncNetworks() {
	//1 full sync all networks
	nws := []model.Network{
		sui.newNetwork("nw1", "10.10.10.0/24"),
		sui.newNetwork("nw2", "20.20.20.0/24"),
	}
	ctx := context.TODO()
	w := sui.regWriter()
	e := w.SyncNetworks(ctx, nws, NoScope)
	sui.Require().NoError(e)
	e = w.SyncNetworks(ctx, nws, NoScope)
	sui.Require().NoError(e)
	e = w.Commit()
	sui.Require().NoError(e)
	r := sui.regReader()
	var nws1 []model.Network
	e = r.ListNetworks(ctx, func(network model.Network) error {
		nws1 = append(nws1, network)
		return nil
	}, NoScope)
	sui.Require().NoError(e)
	sui.Require().Equal(nws, nws1)

	//2 full re-sync all networks
	nws = []model.Network{
		sui.newNetwork("nw3", "30.30.30.0/24"),
		sui.newNetwork("nw4", "40.40.40.0/24"),
	}
	w = sui.regWriter()
	e = w.SyncNetworks(ctx, nws, NoScope)
	sui.Require().NoError(e)
	e = w.Commit()
	sui.Require().NoError(e)
	nws1 = nws1[:0]
	r = sui.regReader()
	e = r.ListNetworks(ctx, func(network model.Network) error {
		nws1 = append(nws1, network)
		return nil
	}, NoScope)
	sui.Require().NoError(e)
	sui.Require().Equal(nws, nws1)

	//3 update existing networks
	nws = []model.Network{
		sui.newNetwork("nw3", "31.31.31.0/24"),
		sui.newNetwork("nw4", "41.41.41.0/24"),
	}
	w = sui.regWriter()
	e = w.SyncNetworks(ctx, nws, NoScope, SyncOmitInsert{}, SyncOmitDelete{})
	sui.Require().NoError(e)
	e = w.Commit()
	sui.Require().NoError(e)
	nws1 = nws1[:0]
	r = sui.regReader()
	e = r.ListNetworks(ctx, func(network model.Network) error {
		nws1 = append(nws1, network)
		return nil
	}, NoScope)
	sui.Require().NoError(e)
	sui.Require().Equal(nws, nws1)

	//5 delete one existing network
	w = sui.regWriter()
	e = w.SyncNetworks(ctx, nil, NetworkNames(nws[0].Name))
	sui.Require().NoError(e)
	e = w.Commit()
	sui.Require().NoError(e)
	n := 0
	r = sui.regReader()
	e = r.ListNetworks(ctx, func(network model.Network) error {
		n++
		return nil
	}, NoScope)
	sui.Require().NoError(e)
	sui.Require().Equal(1, n)
}

func (sui *memDbSuite) TestSyncSG_NoNetworks() {
	//1 - full sync SG(s)
	sgs := []model.SecurityGroup{
		sui.newSG("sg1"),
		sui.newSG("sg2"),
	}
	ctx := context.TODO()
	w := sui.regWriter()
	e := w.SyncSecurityGroups(ctx, sgs, NoScope)
	sui.Require().NoError(e)
	e = w.SyncSecurityGroups(ctx, sgs, NoScope)
	sui.Require().NoError(e)
	e = w.Commit()
	sui.Require().NoError(e)
	r := sui.regReader()
	var sgs1 []model.SecurityGroup
	e = r.ListSecurityGroups(ctx, func(sg model.SecurityGroup) error {
		sgs1 = append(sgs1, sg)
		return nil
	}, NoScope)
	sui.Require().NoError(e)
	sui.Require().Equal(sgs, sgs1)

	//2 - delete one SG 'sg1'
	w = sui.regWriter()
	e = w.SyncSecurityGroups(ctx, nil, SG("sg1"))
	sui.Require().NoError(e)
	e = w.Commit()
	sui.Require().NoError(e)
	r = sui.regReader()
	sgs1 = sgs1[:0]
	e = r.ListSecurityGroups(ctx, func(sg model.SecurityGroup) error {
		sgs1 = append(sgs1, sg)
		return nil
	}, NoScope)
	sui.Require().NoError(e)
	sui.Require().Equal(sgs[1:], sgs1)
}

func (sui *memDbSuite) TestSyncSG_Networks() {
	ctx := context.TODO()

	nw1 := sui.newNetwork("nw1", "10.10.10.0/24")
	nw2 := sui.newNetwork("nw2", "20.20.20.0/24")
	sg1 := sui.newSG("sg1", nw1)
	sg2 := sui.newSG("sg2", nw2)

	w := sui.regWriter()
	err := w.SyncSecurityGroups(ctx, []model.SecurityGroup{sg1}, NoScope)
	sui.Require().NoError(err)
	err = w.Commit()
	sui.Require().Error(err)

	w = sui.regWriter()
	err = w.SyncNetworks(ctx, []model.Network{nw1, nw2}, NoScope)
	sui.Require().NoError(err)
	err = w.Commit()
	sui.Require().NoError(err)

	w = sui.regWriter()
	sg3 := sui.newSG("sg3", nw1)
	sg4 := sui.newSG("sg4", nw2)
	err = w.SyncSecurityGroups(ctx, []model.SecurityGroup{sg1, sg2, sg3, sg4},
		NoScope)
	sui.Require().NoError(err)
	err = w.Commit()
	sui.Require().Error(err)

	w = sui.regWriter()
	err = w.SyncSecurityGroups(ctx, []model.SecurityGroup{sg1, sg2},
		NoScope)
	sui.Require().NoError(err)
	err = w.Commit()
	sui.Require().NoError(err)
	r := sui.regReader()
	var sgs1 []model.SecurityGroup
	err = r.ListSecurityGroups(ctx, func(sg model.SecurityGroup) error {
		sgs1 = append(sgs1, sg)
		return nil
	}, NoScope)
	sui.Require().NoError(err)
	sui.Require().Equal([]model.SecurityGroup{sg1, sg2}, sgs1)

	w = sui.regWriter()
	err = w.SyncNetworks(ctx, nil, NetworkNames("nw2"))
	sui.Require().NoError(err)
	err = w.Commit()
	sui.Require().NoError(err)
	r = sui.regReader()
	sgs1 = sgs1[:0]
	err = r.ListSecurityGroups(ctx, func(sg model.SecurityGroup) error {
		sgs1 = append(sgs1, sg)
		return nil
	}, NoScope)
	sui.Require().NoError(err)
	sg2.Networks = sg2.Networks[:0]
	sui.Require().Equal([]model.SecurityGroup{sg1, sg2}, sgs1)
}

func (sui *memDbSuite) TestSyncSGRules() {
	ctx := context.TODO()

	p := func(s, d model.PortSource) model.SGRulePorts {
		return sui.newRulePorts(s, d)
	}

	nw1 := sui.newNetwork("nw1", "10.10.10.0/24")
	nw2 := sui.newNetwork("nw2", "20.20.20.0/24")
	sg1 := sui.newSG("sg1", nw1)
	sg2 := sui.newSG("sg2", nw2)

	//add networks into DB
	w := sui.regWriter()
	err := w.SyncNetworks(ctx, []model.Network{nw1, nw2}, NoScope)
	sui.Require().NoError(err)
	err = w.Commit()
	sui.Require().NoError(err)

	r1 := sui.newSGRule(sg1.Name, sg2.Name, model.TCP, p("10", "10"), p("20", "20"))
	r2 := sui.newSGRule(sg1.Name, sg2.Name, model.UDP, p("10", "10"), p("20", ""))
	{
		eq := r1.ID.IsEq(r2.ID)
		sui.Require().False(eq)
	}

	//write fails if no SG in DB /- no references to SG(s)
	w = sui.regWriter()
	err = w.SyncSGRules(ctx, []model.SGRule{r1, r2}, NoScope)
	sui.Require().NoError(err)
	err = w.Commit()
	sui.Require().Error(err)

	//write SG(s) to DB
	w = sui.regWriter()
	err = w.SyncSecurityGroups(ctx, []model.SecurityGroup{sg1, sg2}, NoScope)
	sui.Require().NoError(err)
	err = w.Commit()
	sui.Require().NoError(err)

	//write Rules to DB
	w = sui.regWriter()
	err = w.SyncSGRules(ctx, []model.SGRule{r1, r2}, NoScope)
	sui.Require().NoError(err)
	err = w.Commit()
	sui.Require().NoError(err)

	//check if rules are in DB
	reader := sui.regReader()
	rules := make(map[string]model.SGRule)
	rules0 := map[string]model.SGRule{
		r1.ID.IdentityHash(): r1,
		r2.ID.IdentityHash(): r2,
	}
	err = reader.ListSGRules(ctx, func(rule model.SGRule) error {
		rules[rule.ID.IdentityHash()] = rule
		return nil
	}, NoScope)
	sui.Require().NoError(err)
	sui.Require().Equal(len(rules0), len(rules))
	for k, v := range rules0 {
		rule, ok := rules[k]
		sui.Require().Truef(ok, "%s)", v.ID)
		sui.Require().Truef(v.IsEq(rule), "%s)", v.ID)
	}

	//delete one Rule from DB
	w = sui.regWriter()
	err = w.SyncSGRules(ctx, nil, PKScopeOfSGRules(r1))
	sui.Require().NoError(err)
	err = w.Commit()
	sui.Require().NoError(err)
	//expect one rule is in DB
	reader = sui.regReader()
	var cRules int
	err = reader.ListSGRules(ctx, func(rule model.SGRule) error {
		cRules++
		return nil
	}, NoScope)
	sui.Require().NoError(err)
	sui.Require().Equal(1, cRules)

	//Delete one SG from DB
	w = sui.regWriter()
	err = w.SyncSecurityGroups(ctx, nil, SG(sg1.Name))
	sui.Require().NoError(err)
	err = w.Commit()
	sui.Require().NoError(err)
	//expect no any rule is in DB
	reader = sui.regReader()
	cRules = 0
	err = reader.ListSGRules(ctx, func(rule model.SGRule) error {
		cRules++
		return nil
	}, NoScope)
	sui.Require().NoError(err)
	sui.Require().Equal(0, cRules)
}

func (sui *memDbSuite) newCidrSgRule(proto model.NetworkTransport, cidr string, sg string,
	traffic model.Traffic, ports ...model.SGRulePorts) model.CidrSgRule {

	return model.CidrSgRule{
		ID: model.CidrSgRuleIdenity{
			Transport: proto,
			CIDR:      sui.newIPNet(cidr),
			SG:        sg,
			Traffic:   traffic,
		},
		Ports:  ports,
		Action: model.ACCEPT,
	}
}

func (sui *memDbSuite) TestSync_CidrSgRules_FailNoSG() {
	ctx := context.TODO()
	rules := []model.CidrSgRule{sui.newCidrSgRule(
		model.TCP,
		"1.1.1.1/32",
		"sg1",
		model.EGRESS,
	)}
	w := sui.regWriter()
	err := w.SyncCidrSgRules(ctx, rules, NoScope)
	sui.Require().NoError(err)
	err = w.Commit()
	sui.Require().Error(err)
	sui.Require().Contains(err.Error(), "not found ref to SG")
}

func (sui *memDbSuite) Test_CidrSgRules_List() {
	ctx := context.TODO()

	sg1 := sui.newSG("sg1")
	sg2 := sui.newSG("sg2")
	w := sui.regWriter()
	err := w.SyncSecurityGroups(ctx, []model.SecurityGroup{sg1, sg2}, NoScope)
	sui.Require().NoError(err)
	err = w.Commit()
	sui.Require().NoError(err)

	rule1 := sui.newCidrSgRule(
		model.TCP,
		"1.1.1.1/32",
		sg1.Name,
		model.EGRESS,
	)
	rule2 := sui.newCidrSgRule(
		model.UDP,
		"1.1.1.1/32",
		sg2.Name,
		model.INGRESS,
	)
	w = sui.regWriter()
	err = w.SyncCidrSgRules(ctx, []model.CidrSgRule{rule1, rule2}, NoScope)
	sui.Require().NoError(err)
	err = w.Commit()
	sui.Require().NoError(err)

	var allRules dict.HDict[string, model.CidrSgRule]
	var allRules2check dict.HDict[string, model.CidrSgRule]
	_ = allRules.Insert(rule1.ID.String(), rule1)
	_ = allRules.Insert(rule2.ID.String(), rule2)
	sui.Require().Equal(2, allRules.Len())
	r := sui.regReader()
	for _, sc := range []Scope{NoScope, SG(sg1.Name, sg2.Name)} {
		err = r.ListCidrSgRules(ctx, func(csr model.CidrSgRule) error {
			allRules2check.Insert(csr.ID.String(), csr)
			return nil
		}, sc)
		sui.Require().NoError(err)
		sui.Require().Equal(allRules.Len(), allRules2check.Len())
		eq := allRules.Eq(&allRules2check, func(vL, vR model.CidrSgRule) bool {
			return vL.IsEq(vR)
		})
		sui.Require().True(eq)
		allRules2check.Clear()
	}

	expRules := []model.CidrSgRule{rule1, rule2}
	for i, sg := range []model.SecurityGroup{sg1, sg2} {
		var retRule *model.CidrSgRule
		err = r.ListCidrSgRules(ctx, func(csr model.CidrSgRule) error {
			retRule = &csr
			return nil
		}, SG(sg.Name))
		sui.Require().NoError(err)
		sui.Require().NotNil(retRule)
		sui.Require().True(expRules[i].IsEq(*retRule))
	}
}

func (sui *memDbSuite) Test_CidrSgRules_DelSG() {
	ctx := context.TODO()

	sg1 := sui.newSG("sg1")
	sg2 := sui.newSG("sg2")
	w := sui.regWriter()
	err := w.SyncSecurityGroups(ctx, []model.SecurityGroup{sg1, sg2}, NoScope)
	sui.Require().NoError(err)
	err = w.Commit()
	sui.Require().NoError(err)

	rule1 := sui.newCidrSgRule(
		model.TCP,
		"1.1.1.1/32",
		sg1.Name,
		model.EGRESS,
	)
	rule2 := sui.newCidrSgRule(
		model.UDP,
		"1.1.1.1/32",
		sg2.Name,
		model.INGRESS,
	)
	w = sui.regWriter()
	err = w.SyncCidrSgRules(ctx, []model.CidrSgRule{rule1, rule2}, NoScope)
	sui.Require().NoError(err)
	err = w.Commit()
	sui.Require().NoError(err)

	w = sui.regWriter()
	err = w.SyncSecurityGroups(ctx, nil, SG(sg1.Name))
	sui.Require().NoError(err)
	err = w.Commit()
	sui.Require().NoError(err)

	r := sui.regReader()
	var rules []model.CidrSgRule
	err = r.ListCidrSgRules(ctx, func(csr model.CidrSgRule) error {
		rules = append(rules, csr)
		return nil
	}, NoScope)
	sui.Require().NoError(err)
	sui.Require().Equal(1, len(rules))
	sui.Require().True(rules[0].IsEq(rule2))
}

func (sui *memDbSuite) Test_CidrSgRules_IntersectCIDRS() {
	ctx := context.TODO()

	w := sui.regWriter()
	sg1 := sui.newSG("sg1")
	err := w.SyncSecurityGroups(ctx, []model.SecurityGroup{sg1}, NoScope)
	sui.Require().NoError(err)

	rule1 := sui.newCidrSgRule(
		model.UDP,
		"1.1.1.100/32",
		sg1.Name,
		model.EGRESS,
	)
	rule2 := sui.newCidrSgRule(
		model.TCP,
		"1.1.1.1/24",
		sg1.Name,
		model.EGRESS,
	)
	rule3 := sui.newCidrSgRule(
		model.UDP,
		"1.1.1.101/32",
		sg1.Name,
		model.EGRESS,
	)
	rule4 := sui.newCidrSgRule(
		model.UDP,
		"1.1.1.1/24",
		sg1.Name,
		model.EGRESS,
	)
	err = w.SyncCidrSgRules(ctx,
		[]model.CidrSgRule{rule1, rule2, rule3, rule4},
		NoScope)
	sui.Require().NoError(err)
	err = w.Commit()
	sui.Require().Error(err)
	sui.Require().Contains(err.Error(), "have CIDRS with intersected")
}

func (sui *memDbSuite) Test_CidrSgRules_NoIntersectCIDRS() {
	ctx := context.TODO()

	w := sui.regWriter()
	sg1 := sui.newSG("sg1")
	err := w.SyncSecurityGroups(ctx, []model.SecurityGroup{sg1}, NoScope)
	sui.Require().NoError(err)

	rule1 := sui.newCidrSgRule(
		model.UDP,
		"1.1.1.100/32",
		sg1.Name,
		model.EGRESS,
	)
	rule2 := sui.newCidrSgRule(
		model.TCP,
		"1.1.1.1/24",
		sg1.Name,
		model.EGRESS,
	)
	rule3 := sui.newCidrSgRule(
		model.UDP,
		"1.1.1.1/24",
		sg1.Name,
		model.INGRESS,
	)
	err = w.SyncCidrSgRules(ctx,
		[]model.CidrSgRule{rule1, rule2, rule3},
		NoScope)
	sui.Require().NoError(err)
	err = w.Commit()
	sui.Require().NoError(err)
}

func (sui *memDbSuite) newCidrSgIcmpRule(traffic model.Traffic, cidr, sg string, ipv uint8) model.CidrSgIcmpRule {
	return model.CidrSgIcmpRule{
		Traffic: traffic,
		CIDR:    sui.newIPNet(cidr),
		SG:      sg,
		Icmp: model.ICMP{
			IPv: ipv,
		},
		Action: model.ACCEPT,
	}
}

func (sui *memDbSuite) TestSync_CidrSgIcmpRules_FailNoSG() {
	ctx := context.TODO()
	rules := []model.CidrSgIcmpRule{sui.newCidrSgIcmpRule(
		model.EGRESS,
		"1.1.1.1/32",
		"sg1",
		model.IPv4)}
	w := sui.regWriter()
	err := w.SyncCidrSgIcmpRules(ctx, rules, NoScope)
	sui.Require().NoError(err)
	err = w.Commit()
	sui.Require().Error(err)
	sui.Require().Contains(err.Error(), "not found ref to SG")
}

func (sui *memDbSuite) Test_CidrSgIcmpRules_List() {
	ctx := context.TODO()

	sg1 := sui.newSG("sg1")
	sg2 := sui.newSG("sg2")
	w := sui.regWriter()
	err := w.SyncSecurityGroups(ctx, []model.SecurityGroup{sg1, sg2}, NoScope)
	sui.Require().NoError(err)
	err = w.Commit()
	sui.Require().NoError(err)

	rule1 := sui.newCidrSgIcmpRule(model.EGRESS, "1.1.1.1/32", sg1.Name, model.IPv4)
	rule2 := sui.newCidrSgIcmpRule(model.INGRESS, "1.1.1.1/32", sg2.Name, model.IPv6)

	w = sui.regWriter()
	err = w.SyncCidrSgIcmpRules(ctx, []model.CidrSgIcmpRule{rule1, rule2}, NoScope)
	sui.Require().NoError(err)
	err = w.Commit()
	sui.Require().NoError(err)

	var allRules dict.HDict[string, model.CidrSgIcmpRule]
	var allRules2check dict.HDict[string, model.CidrSgIcmpRule]
	_ = allRules.Insert(rule1.ID().String(), rule1)
	_ = allRules.Insert(rule2.ID().String(), rule2)
	sui.Require().Equal(2, allRules.Len())
	r := sui.regReader()
	for _, sc := range []Scope{NoScope, SG(sg1.Name, sg2.Name)} {
		err = r.ListCidrSgIcmpRules(ctx, func(r model.CidrSgIcmpRule) error {
			allRules2check.Insert(r.ID().String(), r)
			return nil
		}, sc)
		sui.Require().NoError(err)
		sui.Require().Equal(allRules.Len(), allRules2check.Len())
		eq := allRules.Eq(&allRules2check, func(vL, vR model.CidrSgIcmpRule) bool {
			return vL.IsEq(vR)
		})
		sui.Require().True(eq)
		allRules2check.Clear()
	}

	expRules := []model.CidrSgIcmpRule{rule1, rule2}
	for i, sg := range []model.SecurityGroup{sg1, sg2} {
		var retRule *model.CidrSgIcmpRule
		err = r.ListCidrSgIcmpRules(ctx, func(r model.CidrSgIcmpRule) error {
			retRule = &r
			return nil
		}, SG(sg.Name))
		sui.Require().NoError(err)
		sui.Require().NotNil(retRule)
		sui.Require().True(expRules[i].IsEq(*retRule))
	}
}

func (sui *memDbSuite) Test_CidrSgIcmpRules_DelSG() {
	ctx := context.TODO()

	sg1 := sui.newSG("sg1")
	sg2 := sui.newSG("sg2")
	w := sui.regWriter()
	err := w.SyncSecurityGroups(ctx, []model.SecurityGroup{sg1, sg2}, NoScope)
	sui.Require().NoError(err)
	err = w.Commit()
	sui.Require().NoError(err)

	rule1 := sui.newCidrSgIcmpRule(model.EGRESS, "1.1.1.1/32", sg1.Name, model.IPv4)
	rule2 := sui.newCidrSgIcmpRule(model.INGRESS, "1.1.1.1/32", sg2.Name, model.IPv6)

	w = sui.regWriter()
	err = w.SyncCidrSgIcmpRules(ctx, []model.CidrSgIcmpRule{rule1, rule2}, NoScope)
	sui.Require().NoError(err)
	err = w.Commit()
	sui.Require().NoError(err)

	w = sui.regWriter()
	err = w.SyncSecurityGroups(ctx, nil, SG(sg1.Name))
	sui.Require().NoError(err)
	err = w.Commit()
	sui.Require().NoError(err)

	r := sui.regReader()
	var rules []model.CidrSgIcmpRule
	err = r.ListCidrSgIcmpRules(ctx, func(csr model.CidrSgIcmpRule) error {
		rules = append(rules, csr)
		return nil
	}, NoScope)
	sui.Require().NoError(err)
	sui.Require().Equal(1, len(rules))
	sui.Require().True(rules[0].IsEq(rule2))
}

func (sui *memDbSuite) Test_CidrSgIcmpRules_IntersectCIDRS() {
	ctx := context.TODO()

	w := sui.regWriter()
	sg1 := sui.newSG("sg1")
	err := w.SyncSecurityGroups(ctx, []model.SecurityGroup{sg1}, NoScope)
	sui.Require().NoError(err)

	rule1 := sui.newCidrSgIcmpRule(model.EGRESS, "1.1.1.100/32", sg1.Name, model.IPv4)
	rule2 := sui.newCidrSgIcmpRule(model.EGRESS, "1.1.1.1/24", sg1.Name, model.IPv6)
	rule3 := sui.newCidrSgIcmpRule(model.EGRESS, "1.1.1.101/32", sg1.Name, model.IPv4)
	rule4 := sui.newCidrSgIcmpRule(model.EGRESS, "1.1.1.1/24", sg1.Name, model.IPv4)

	err = w.SyncCidrSgIcmpRules(ctx,
		[]model.CidrSgIcmpRule{rule1, rule2, rule3, rule4},
		NoScope)
	sui.Require().NoError(err)
	err = w.Commit()
	sui.Require().Error(err)
	sui.Require().Contains(err.Error(), "have CIDRS with intersected")
}

func (sui *memDbSuite) Test_CidrSgIcmpRules_NoIntersectCIDRS() {
	ctx := context.TODO()

	w := sui.regWriter()
	sg1 := sui.newSG("sg1")
	err := w.SyncSecurityGroups(ctx, []model.SecurityGroup{sg1}, NoScope)
	sui.Require().NoError(err)

	rule1 := sui.newCidrSgIcmpRule(model.EGRESS, "1.1.1.100/32", sg1.Name, model.IPv4)
	rule2 := sui.newCidrSgIcmpRule(model.EGRESS, "1.1.1.1/24", sg1.Name, model.IPv6)
	rule3 := sui.newCidrSgIcmpRule(model.INGRESS, "1.1.1.1/24", sg1.Name, model.IPv4)

	err = w.SyncCidrSgIcmpRules(ctx,
		[]model.CidrSgIcmpRule{rule1, rule2, rule3},
		NoScope)
	sui.Require().NoError(err)
	err = w.Commit()
	sui.Require().NoError(err)
}

func (sui *memDbSuite) newSgSgRule(proto model.NetworkTransport, sgLocal, sg string,
	traffic model.Traffic, ports ...model.SGRulePorts) model.SgSgRule {

	return model.SgSgRule{
		ID: model.SgSgRuleIdentity{
			Transport: proto,
			Traffic:   traffic,
			SgLocal:   sgLocal,
			Sg:        sg,
		},
		Ports:  ports,
		Action: model.ACCEPT,
	}
}

func (sui *memDbSuite) TestSync_SgSgRules_FailNoSG() {
	ctx := context.TODO()
	rules := []model.SgSgRule{sui.newSgSgRule(
		model.TCP,
		"sg1",
		"sg2",
		model.EGRESS)}
	w := sui.regWriter()
	err := w.SyncSgSgRules(ctx, rules, NoScope)
	sui.Require().NoError(err)
	err = w.Commit()
	sui.Require().Error(err)
	sui.Require().Contains(err.Error(), "not found ref to SgLocal")
}

func (sui *memDbSuite) Test_SgSgRules_List() {
	ctx := context.TODO()

	sg1 := sui.newSG("sg1")
	sg2 := sui.newSG("sg2")
	sg3 := sui.newSG("sg3")
	sg4 := sui.newSG("sg4")
	w := sui.regWriter()
	err := w.SyncSecurityGroups(ctx, []model.SecurityGroup{sg1, sg2, sg3, sg4}, NoScope)
	sui.Require().NoError(err)
	err = w.Commit()
	sui.Require().NoError(err)

	rule1 := sui.newSgSgRule(
		model.TCP,
		sg1.Name,
		sg2.Name,
		model.EGRESS)
	rule2 := sui.newSgSgRule(
		model.UDP,
		sg3.Name,
		sg4.Name,
		model.INGRESS)

	w = sui.regWriter()
	err = w.SyncSgSgRules(ctx, []model.SgSgRule{rule1, rule2}, NoScope)
	sui.Require().NoError(err)
	err = w.Commit()
	sui.Require().NoError(err)

	var allRules dict.HDict[string, model.SgSgRule]
	var allRules2check dict.HDict[string, model.SgSgRule]
	_ = allRules.Insert(rule1.ID.String(), rule1)
	_ = allRules.Insert(rule2.ID.String(), rule2)
	sui.Require().Equal(2, allRules.Len())
	r := sui.regReader()
	sgLocalScope := SGLocal(sg1.Name, sg3.Name)
	sgScope := SG(sg2.Name, sg4.Name)
	for _, sc := range []Scope{NoScope, sgLocalScope, sgScope, And(sgLocalScope, sgScope)} {
		err = r.ListSgSgRules(ctx, func(r model.SgSgRule) error {
			allRules2check.Insert(r.ID.String(), r)
			return nil
		}, sc)
		sui.Require().NoError(err)
		sui.Require().Equal(allRules.Len(), allRules2check.Len())
		eq := allRules.Eq(&allRules2check, func(vL, vR model.SgSgRule) bool {
			return vL.IsEq(vR)
		})
		sui.Require().True(eq)
		allRules2check.Clear()
	}

	expRules := []model.SgSgRule{rule1, rule2}
	for i, sg := range []model.SecurityGroup{sg1, sg3} {
		var retRule *model.SgSgRule
		err = r.ListSgSgRules(ctx, func(r model.SgSgRule) error {
			retRule = &r
			return nil
		}, SGLocal(sg.Name))
		sui.Require().NoError(err)
		sui.Require().NotNil(retRule)
		sui.Require().True(expRules[i].IsEq(*retRule))
	}
	for i, sg := range []model.SecurityGroup{sg2, sg4} {
		var retRule *model.SgSgRule
		err = r.ListSgSgRules(ctx, func(r model.SgSgRule) error {
			retRule = &r
			return nil
		}, SG(sg.Name))
		sui.Require().NoError(err)
		sui.Require().NotNil(retRule)
		sui.Require().True(expRules[i].IsEq(*retRule))
	}
}

func (sui *memDbSuite) TestSgSgRules_DelSG() {
	ctx := context.TODO()

	sg1 := sui.newSG("sg1")
	sg2 := sui.newSG("sg2")
	sg3 := sui.newSG("sg3")
	sg4 := sui.newSG("sg4")
	w := sui.regWriter()
	err := w.SyncSecurityGroups(ctx, []model.SecurityGroup{sg1, sg2, sg3, sg4}, NoScope)
	sui.Require().NoError(err)
	err = w.Commit()
	sui.Require().NoError(err)

	rule1 := sui.newSgSgRule(
		model.TCP,
		sg1.Name,
		sg2.Name,
		model.EGRESS)
	rule2 := sui.newSgSgRule(
		model.UDP,
		sg3.Name,
		sg4.Name,
		model.INGRESS)

	w = sui.regWriter()
	err = w.SyncSgSgRules(ctx, []model.SgSgRule{rule1, rule2}, NoScope)
	sui.Require().NoError(err)
	err = w.Commit()
	sui.Require().NoError(err)

	w = sui.regWriter()
	err = w.SyncSecurityGroups(ctx, nil, SG(sg1.Name))
	sui.Require().NoError(err)
	err = w.Commit()
	sui.Require().NoError(err)

	r := sui.regReader()
	var rules []model.SgSgRule
	err = r.ListSgSgRules(ctx, func(r model.SgSgRule) error {
		rules = append(rules, r)
		return nil
	}, NoScope)
	sui.Require().NoError(err)
	sui.Require().Equal(1, len(rules))
	sui.Require().True(rules[0].IsEq(rule2))
}

func (sui *memDbSuite) newIESgSgIcmpRule(traffic model.Traffic, sgLocal, sg string, ipv uint8) model.IESgSgIcmpRule {
	return model.IESgSgIcmpRule{
		Traffic: traffic,
		SgLocal: sgLocal,
		Sg:      sg,
		Icmp: model.ICMP{
			IPv: ipv,
		},
		Action: model.ACCEPT,
	}
}

func (sui *memDbSuite) TestSync_IESgSgIcmpRules_FailNoSG() {
	ctx := context.TODO()
	rules := []model.IESgSgIcmpRule{sui.newIESgSgIcmpRule(
		model.EGRESS,
		"sg1",
		"sg2",
		model.IPv4)}
	w := sui.regWriter()
	err := w.SyncIESgSgIcmpRules(ctx, rules, NoScope)
	sui.Require().NoError(err)
	err = w.Commit()
	sui.Require().Error(err)
	sui.Require().Contains(err.Error(), "not found ref to SgLocal")
}

func (sui *memDbSuite) Test_IESgSgRules_List() {
	ctx := context.TODO()

	sg1 := sui.newSG("sg1")
	sg2 := sui.newSG("sg2")
	sg3 := sui.newSG("sg3")
	sg4 := sui.newSG("sg4")
	w := sui.regWriter()
	err := w.SyncSecurityGroups(ctx, []model.SecurityGroup{sg1, sg2, sg3, sg4}, NoScope)
	sui.Require().NoError(err)
	err = w.Commit()
	sui.Require().NoError(err)

	rule1 := sui.newIESgSgIcmpRule(model.EGRESS, sg1.Name, sg2.Name, model.IPv4)
	rule2 := sui.newIESgSgIcmpRule(model.INGRESS, sg3.Name, sg4.Name, model.IPv6)

	w = sui.regWriter()
	err = w.SyncIESgSgIcmpRules(ctx, []model.IESgSgIcmpRule{rule1, rule2}, NoScope)
	sui.Require().NoError(err)
	err = w.Commit()
	sui.Require().NoError(err)

	var allRules dict.HDict[string, model.IESgSgIcmpRule]
	var allRules2check dict.HDict[string, model.IESgSgIcmpRule]
	_ = allRules.Insert(rule1.ID().String(), rule1)
	_ = allRules.Insert(rule2.ID().String(), rule2)
	sui.Require().Equal(2, allRules.Len())
	r := sui.regReader()
	sgLocalScope := SGLocal(sg1.Name, sg3.Name)
	sgScope := SG(sg2.Name, sg4.Name)
	for _, sc := range []Scope{NoScope, sgLocalScope, sgScope, And(sgLocalScope, sgScope)} {
		err = r.ListIESgSgIcmpRules(ctx, func(r model.IESgSgIcmpRule) error {
			allRules2check.Insert(r.ID().String(), r)
			return nil
		}, sc)
		sui.Require().NoError(err)
		sui.Require().Equal(allRules.Len(), allRules2check.Len())
		eq := allRules.Eq(&allRules2check, func(vL, vR model.IESgSgIcmpRule) bool {
			return vL.IsEq(vR)
		})
		sui.Require().True(eq)
		allRules2check.Clear()
	}

	expRules := []model.IESgSgIcmpRule{rule1, rule2}
	for i, sg := range []model.SecurityGroup{sg1, sg3} {
		var retRule *model.IESgSgIcmpRule
		err = r.ListIESgSgIcmpRules(ctx, func(r model.IESgSgIcmpRule) error {
			retRule = &r
			return nil
		}, SGLocal(sg.Name))
		sui.Require().NoError(err)
		sui.Require().NotNil(retRule)
		sui.Require().True(expRules[i].IsEq(*retRule))
	}
	for i, sg := range []model.SecurityGroup{sg2, sg4} {
		var retRule *model.IESgSgIcmpRule
		err = r.ListIESgSgIcmpRules(ctx, func(r model.IESgSgIcmpRule) error {
			retRule = &r
			return nil
		}, SG(sg.Name))
		sui.Require().NoError(err)
		sui.Require().NotNil(retRule)
		sui.Require().True(expRules[i].IsEq(*retRule))
	}
}

func (sui *memDbSuite) TestIESgSgIcmpRules_DelSG() {
	ctx := context.TODO()

	sg1 := sui.newSG("sg1")
	sg2 := sui.newSG("sg2")
	sg3 := sui.newSG("sg3")
	sg4 := sui.newSG("sg4")
	w := sui.regWriter()
	err := w.SyncSecurityGroups(ctx, []model.SecurityGroup{sg1, sg2, sg3, sg4}, NoScope)
	sui.Require().NoError(err)
	err = w.Commit()
	sui.Require().NoError(err)

	rule1 := sui.newIESgSgIcmpRule(model.EGRESS, sg1.Name, sg2.Name, model.IPv4)
	rule2 := sui.newIESgSgIcmpRule(model.INGRESS, sg3.Name, sg4.Name, model.IPv6)

	w = sui.regWriter()
	err = w.SyncIESgSgIcmpRules(ctx, []model.IESgSgIcmpRule{rule1, rule2}, NoScope)
	sui.Require().NoError(err)
	err = w.Commit()
	sui.Require().NoError(err)

	w = sui.regWriter()
	err = w.SyncSecurityGroups(ctx, nil, SG(sg1.Name))
	sui.Require().NoError(err)
	err = w.Commit()
	sui.Require().NoError(err)

	r := sui.regReader()
	var rules []model.IESgSgIcmpRule
	err = r.ListIESgSgIcmpRules(ctx, func(r model.IESgSgIcmpRule) error {
		rules = append(rules, r)
		return nil
	}, NoScope)
	sui.Require().NoError(err)
	sui.Require().Equal(1, len(rules))
	sui.Require().True(rules[0].IsEq(rule2))
}
