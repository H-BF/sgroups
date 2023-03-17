package sgroups

import (
	"context"
	"net"
	"testing"
	"time"

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
	db, err := NewMemDB(TblNetworks, TblSecGroups, TblSecRules, TblSyncStatus,
		IntegrityChecker4SG(), IntegrityChecker4Rules(), IntegrityChecker4Networks())
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

func (sui *memDbSuite) newNetwork(name string, cidr string) model.Network {
	sui.Require().NotEmpty(name)
	var n *net.IPNet
	_, n, err := net.ParseCIDR(cidr)
	sui.Require().NoError(err)
	return model.Network{
		Name: name,
		Net:  *n,
	}
}

func (sui *memDbSuite) newSG(name string, nws ...model.Network) model.SecurityGroup {
	sui.Require().NotEmpty(name)
	ret := model.SecurityGroup{Name: name}
	for i := range nws {
		ret.Networks = append(ret.Networks, nws[i])
	}
	return ret
}

func (sui *memDbSuite) newSGRule(sgFrom, sgTo model.SecurityGroup, t model.NetworkTransport) model.SGRule {
	return model.SGRule{
		SGRuleIdentity: model.SGRuleIdentity{
			Transport: t,
			SgFrom:    sgFrom,
			SgTo:      sgTo,
		}}
}

func (sui *memDbSuite) TestSyncStatus() {
	ctx := context.TODO()
	rd := sui.regReader()
	v, e := rd.GetSyncStatus(ctx)
	sui.Require().NoError(e)
	sui.Require().Nil(v)
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
	v, e = rd.GetSyncStatus(ctx)
	sui.Require().NoError(e)
	sui.Require().NotNil(v)
	sui.Require().Equal(x.UpdatedAt, v.UpdatedAt)
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

	r1 := sui.newSGRule(sg1, sg2, model.TCP)
	r2 := sui.newSGRule(sg1, sg2, model.UDP)
	{
		h1 := r1.IdentityHash()
		h2 := r2.IdentityHash()
		sui.Require().NotEqual(h1, h2)
	}

	//write fails if no SG in DB /- no references to SG(s)
	w = sui.regWriter()
	err = w.SyncSGRules(ctx, []model.SGRule{r1, r2}, NoScope)
	sui.Require().NoError(err)
	err = w.Commit()
	sui.Require().Error(err)

	//Same SG(s) in rule /DB - fail
	w = sui.regWriter()
	err = w.SyncSGRules(ctx,
		[]model.SGRule{sui.newSGRule(sg1, sg1, model.TCP)},
		NoScope)
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
	rr := []model.SGRule{r1, r2}
	w = sui.regWriter()
	err = w.SyncSGRules(ctx, rr, NoScope)
	sui.Require().NoError(err)
	err = w.Commit()
	sui.Require().NoError(err)

	//check if rules are in DB
	reader := sui.regReader()
	rules := make(map[string]model.SGRule)
	err = reader.ListSGRules(ctx, func(rule model.SGRule) error {
		rules[rule.IdentityHash()] = rule
		return nil
	}, NoScope)
	sui.Require().NoError(err)
	for i := range rr {
		rule, ok := rules[rr[i].IdentityHash()]
		sui.Require().Truef(ok, "%v)", i)
		sui.Require().Equalf(rr[i], rule, "%v)", i)
	}

	//delete one Rule from DB
	w = sui.regWriter()
	err = w.SyncSGRules(ctx, nil, SGRule(r1))
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
