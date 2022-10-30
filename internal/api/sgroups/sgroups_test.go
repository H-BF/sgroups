package sgroups

import (
	"context"
	"testing"

	"github.com/H-BF/protos/pkg/api/common"
	api "github.com/H-BF/protos/pkg/api/sgroups"
	model "github.com/H-BF/sgroups/internal/models/sgroups"
	registry "github.com/H-BF/sgroups/internal/registry/sgroups"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

func Test_SGroupsService_MemDB(t *testing.T) {
	sui := &sGroupServiceTests{
		ctx: context.TODO(),
		regMaker: func() registry.Registry {
			m, e := registry.NewMemDB(registry.TblSecGroups,
				registry.TblSecRules, registry.TblNetworks,
				registry.IntegrityChecker4SG(),
				registry.IntegrityChecker4Rules())
			require.NoError(t, e)
			return registry.NewRegistryFromMemDB(m)
		},
	}
	suite.Run(t, sui)
}

type sGroupServiceTests struct {
	suite.Suite

	ctx      context.Context
	regMaker func() registry.Registry
	reg      registry.Registry
	srv      api.SecGroupServiceServer
}

func (sui *sGroupServiceTests) SetupTest() {
	sui.Require().Nil(sui.srv)
	sui.Require().Nil(sui.reg)
	sui.Require().NotNil(sui.regMaker)
	sui.reg = sui.regMaker()
	sui.srv = NewSGroupsService(sui.ctx, sui.reg).(api.SecGroupServiceServer)
}

func (sui *sGroupServiceTests) TearDownTest() {
	if sui.reg != nil {
		_ = sui.reg.Close()
		sui.reg = nil
	}
	sui.srv = nil
}

func (sui *sGroupServiceTests) reader() registry.Reader {
	r, e := sui.reg.Reader(sui.ctx)
	sui.Require().NoError(e)
	return r
}

func (sui *sGroupServiceTests) newNetwork(name, cidr string) *api.Network {
	return &api.Network{
		Name: name,
		Network: &common.Networks_NetIP{
			CIDR: cidr,
		},
	}
}

func (sui *sGroupServiceTests) network2model(nws ...*api.Network) []model.Network {
	var ret []model.Network
	var s network
	for i := range nws {
		e := s.from(nws[i])
		sui.Require().NoError(e)
		ret = append(ret, s.Network)
	}
	return ret
}

func (sui *sGroupServiceTests) syncNetworks(nws []*api.Network, op api.SyncReq_SyncOp) {
	req := api.SyncReq{
		SyncOp: op,
		Subject: &api.SyncReq_Networks{
			Networks: &api.SyncNetworks{
				Networks: nws,
			},
		},
	}
	_, err := sui.srv.Sync(sui.ctx, &req)
	sui.Require().NoError(err)
}

func (sui *sGroupServiceTests) Test_Sync_Networks() {
	nw1 := sui.newNetwork("net1", "10.10.10.0/24")
	nw2 := sui.newNetwork("net2", "10.10.20.0/24")
	sui.syncNetworks([]*api.Network{nw1, nw2}, api.SyncReq_FullSync)
	r := sui.reader()
	m := make(map[model.NetworkName]model.Network)
	err := r.ListNetworks(sui.ctx, func(nw model.Network) error {
		m[nw.Name] = nw
		return nil
	}, registry.NoScope)
	sui.Require().NoError(err)
	for _, exp := range sui.network2model(nw1, nw2) {
		n1, ok := m[exp.Name]
		sui.Require().Truef(ok, "expected network '%s'", exp.Name)
		sui.Require().Equal(exp, n1)
	}
	sui.syncNetworks([]*api.Network{nw1, nw2}, api.SyncReq_Delete)
	r = sui.reader()
	var cnt int
	err = r.ListNetworks(sui.ctx, func(nw model.Network) error {
		cnt++
		return nil
	}, registry.NoScope)
	sui.Require().NoError(err)
	sui.Require().Equal(0, cnt)
}

func (sui *sGroupServiceTests) syncSGs(sgs []*api.SecGroup, op api.SyncReq_SyncOp) {
	req := api.SyncReq{
		SyncOp: op,
		Subject: &api.SyncReq_Groups{
			Groups: &api.SyncSecurityGroups{
				Groups: sgs,
			},
		},
	}
	_, err := sui.srv.Sync(sui.ctx, &req)
	sui.Require().NoError(err)
}

func (sui *sGroupServiceTests) newSG(name string, nws ...*api.Network) *api.SecGroup {
	return &api.SecGroup{
		Name:     name,
		Networks: nws,
	}
}

func (sui *sGroupServiceTests) Test_Sync_SecGroups() {
	nw1 := sui.newNetwork("net1", "10.10.10.0/24")
	nw2 := sui.newNetwork("net2", "10.10.20.0/24")
	sui.syncNetworks([]*api.Network{nw1, nw2}, api.SyncReq_FullSync)

	sg1 := sui.newSG("sg1", nw1)
	sg2 := sui.newSG("sg2", nw2)
	sui.syncSGs([]*api.SecGroup{sg1, sg2}, api.SyncReq_FullSync)

	r := sui.reader()
	m := make(map[string]bool)
	err := r.ListSecurityGroups(sui.ctx, func(group model.SecurityGroup) error {
		m[group.Name] = true
		return nil
	}, registry.NoScope)
	sui.Require().NoError(err)
	for _, o := range []*api.SecGroup{sg1, sg2} {
		ok := m[o.GetName()]
		sui.Require().Truef(ok, "required SG '%s'", o.GetName())
	}

	sui.syncSGs([]*api.SecGroup{sg1, sg2}, api.SyncReq_Delete)
	var cn int
	r = sui.reader()
	err = r.ListSecurityGroups(sui.ctx, func(_ model.SecurityGroup) error {
		cn++
		return nil
	}, registry.NoScope)
	sui.Require().NoError(err)
	sui.Require().Equal(0, cn)
}

func (sui *sGroupServiceTests) newRule(from, to *api.SecGroup, tr common.Networks_NetIP_Transport) *api.Rule {
	return &api.Rule{
		SgFrom:    from,
		SgTo:      to,
		Transport: tr,
	}
}

func (sui *sGroupServiceTests) syncRules(rules []*api.Rule, op api.SyncReq_SyncOp) {
	req := api.SyncReq{
		SyncOp: op,
		Subject: &api.SyncReq_SgRules{
			SgRules: &api.SyncSGRules{
				Rules: rules,
			},
		},
	}
	_, err := sui.srv.Sync(sui.ctx, &req)
	sui.Require().NoError(err)
}

func (sui *sGroupServiceTests) rule2Id(rules ...*api.Rule) []model.SGRuleIdentity {
	var ret []model.SGRuleIdentity
	var sg securityGroup
	for _, r := range rules {
		var id model.SGRuleIdentity
		sg.from(r.GetSgFrom())
		id.SgFrom = sg.SecurityGroup
		sg.from(r.GetSgTo())
		id.SgTo = sg.SecurityGroup
		err := (networkTransport{&id.Transport}).
			from(r.GetTransport())
		sui.Require().NoError(err)
		ret = append(ret, id)
	}
	return ret
}

func (sui *sGroupServiceTests) Test_Sync_Rules() {
	sg1 := sui.newSG("sg1")
	sg2 := sui.newSG("sg2")
	sui.syncSGs([]*api.SecGroup{sg1, sg2}, api.SyncReq_FullSync)

	rule1 := sui.newRule(sg1, sg2, common.Networks_NetIP_TCP)
	rule2 := sui.newRule(sg1, sg2, common.Networks_NetIP_UDP)
	sui.syncRules([]*api.Rule{rule1, rule2}, api.SyncReq_FullSync)

	r := sui.reader()
	m := make(map[string]bool)
	err := r.ListSGRules(sui.ctx, func(rule model.SGRule) error {
		m[rule.IdentityHash()] = true
		return nil
	}, registry.NoScope)
	sui.Require().NoError(err)
	ids := sui.rule2Id(rule1, rule2)
	for _, x := range ids {
		ok := m[x.IdentityHash()]
		sui.Require().Truef(ok, "required rule '%s'", x)
	}

	sui.syncRules([]*api.Rule{rule1, rule2}, api.SyncReq_Delete)
	r = sui.reader()
	var cn int
	err = r.ListSGRules(sui.ctx, func(_ model.SGRule) error {
		cn++
		return nil
	}, registry.NoScope)
	sui.Require().NoError(err)
	sui.Require().Equal(0, cn)

	sui.syncRules([]*api.Rule{rule1, rule2}, api.SyncReq_FullSync)
	sui.syncSGs([]*api.SecGroup{sg1}, api.SyncReq_Delete)
	r = sui.reader()
	err = r.ListSGRules(sui.ctx, func(_ model.SGRule) error {
		cn++
		return nil
	}, registry.NoScope)
	sui.Require().NoError(err)
	sui.Require().Equal(0, cn)
}
