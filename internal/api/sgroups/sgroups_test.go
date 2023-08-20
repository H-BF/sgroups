package sgroups

import (
	"context"
	"testing"

	model "github.com/H-BF/sgroups/internal/models/sgroups"
	registry "github.com/H-BF/sgroups/internal/registry/sgroups"

	"github.com/H-BF/protos/pkg/api/common"
	api "github.com/H-BF/protos/pkg/api/sgroups"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func Test_SGroupsService_MemDB(t *testing.T) {
	sui := &sGroupServiceTests{
		ctx: context.TODO(),
		regMaker: func() registry.Registry {
			m, e := registry.NewMemDB(registry.TblSecGroups,
				registry.TblSecRules, registry.TblNetworks,
				registry.TblSyncStatus,
				registry.IntegrityChecker4SG(),
				registry.IntegrityChecker4Rules(),
				registry.IntegrityChecker4Networks())
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

func (sui *sGroupServiceTests) newSG(name string, nws ...string) *api.SecGroup {
	return &api.SecGroup{
		Name:     name,
		Networks: nws,
	}
}

func (sui *sGroupServiceTests) newPorts(s, d string) *api.Rule_Ports {
	return &api.Rule_Ports{S: s, D: d}
}

func (sui *sGroupServiceTests) Test_Sync_SecGroups() {
	nw1 := sui.newNetwork("net1", "10.10.10.0/24")
	nw2 := sui.newNetwork("net2", "10.10.20.0/24")
	sui.syncNetworks([]*api.Network{nw1, nw2}, api.SyncReq_FullSync)

	sg1 := sui.newSG("sg1", nw1.Name)
	sg2 := sui.newSG("sg2", nw2.Name)
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

func (sui *sGroupServiceTests) newRule(from, to *api.SecGroup, tr common.Networks_NetIP_Transport, ports ...*api.Rule_Ports) *api.Rule {
	return &api.Rule{
		SgFrom:    from.Name,
		SgTo:      to.Name,
		Transport: tr,
		Ports:     ports,
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
	for _, r := range rules {
		var id model.SGRuleIdentity
		id.SgFrom = r.SgFrom
		id.SgTo = r.SgTo
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

	rule1 := sui.newRule(sg1, sg2, common.Networks_NetIP_TCP, sui.newPorts("100-200", "80"))
	rule2 := sui.newRule(sg1, sg2, common.Networks_NetIP_UDP, sui.newPorts("100-200", "80"))
	sui.syncRules([]*api.Rule{rule1, rule2}, api.SyncReq_FullSync)

	r := sui.reader()
	m := make(map[string]bool)
	err := r.ListSGRules(sui.ctx, func(rule model.SGRule) error {
		m[rule.ID.IdentityHash()] = true
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

func (sui *sGroupServiceTests) Test_GetSecGroupForAddress() {
	nw1 := sui.newNetwork("net1", "10.10.10.0/24")
	nw2 := sui.newNetwork("net2", "20.20.20.0/24")
	sui.syncNetworks([]*api.Network{nw1, nw2}, api.SyncReq_FullSync)

	sg1 := sui.newSG("sg1", nw1.Name)
	sg2 := sui.newSG("sg2", nw2.Name)
	sui.syncSGs([]*api.SecGroup{sg1, sg2}, api.SyncReq_FullSync)

	tst := []struct {
		ip    string
		expSg *api.SecGroup
	}{
		{"10.10.10.2", sg1},
		{"20.20.20.1", sg2},
		{"30.30.30.1", nil},
	}
	for i := range tst {
		t := tst[i]
		req := api.GetSecGroupForAddressReq{
			Address: t.ip,
		}
		resp, err := sui.srv.GetSecGroupForAddress(sui.ctx, &req)
		if t.expSg == nil {
			sui.Require().Error(err)
			sui.Require().Equal(codes.NotFound, status.Code(err))
		} else {
			sui.Require().Equal(t.expSg.GetName(), resp.GetName())
		}
	}
}

func (sui *sGroupServiceTests) Test_GetSgSubnets() {
	nw1 := sui.newNetwork("net1", "10.10.10.0/24")
	nw2 := sui.newNetwork("net2", "20.20.20.0/24")
	sui.syncNetworks([]*api.Network{nw1, nw2}, api.SyncReq_FullSync)

	sg1 := sui.newSG("sg1", nw1.Name)
	sg2 := sui.newSG("sg2", nw2.Name)
	sg3 := sui.newSG("sg3")
	sui.syncSGs([]*api.SecGroup{sg1, sg2, sg3}, api.SyncReq_FullSync)

	tests := []struct {
		sg         string
		expNet     string
		shouldFail bool
		ec         codes.Code
	}{
		{"sg1", "net1", false, 0},
		{"sg2", "net2", false, 0},
		{"sg3", "", true, codes.NotFound},
		{"sg4", "", true, codes.NotFound},
	}
	req := new(api.GetSgSubnetsReq)
	for i, t := range tests {
		req.SgName = t.sg
		resp, err := sui.srv.GetSgSubnets(sui.ctx, req)
		if t.shouldFail {
			sui.Require().Errorf(err, "when do test #%v", i)
			c := status.Code(err)
			sui.Require().Equalf(t.ec, c, "when do test #%v", i)
		} else {
			nws := resp.GetNetworks()
			sui.Require().Equalf(1, len(nws), "when do test #%v", i)
			sui.Require().Equalf(t.expNet, nws[0].GetName(), "when do test #%v", i)
		}
	}
}

func (sui *sGroupServiceTests) Test_GetRules() {
	nw1 := sui.newNetwork("net1", "10.10.10.0/24")
	nw2 := sui.newNetwork("net2", "20.20.20.0/24")
	nw3 := sui.newNetwork("net3", "25.20.20.0/24")
	sui.syncNetworks([]*api.Network{nw1, nw2, nw3}, api.SyncReq_FullSync)

	sg1 := sui.newSG("sg1", nw1.Name)
	sg2 := sui.newSG("sg2", nw2.Name)
	sg3 := sui.newSG("sg3", nw3.Name)
	sui.syncSGs([]*api.SecGroup{sg1, sg2, sg3}, api.SyncReq_FullSync)

	r1 := sui.newRule(sg1, sg2, common.Networks_NetIP_TCP)
	r2 := sui.newRule(sg1, sg3, common.Networks_NetIP_UDP)
	r3 := sui.newRule(sg2, sg1, common.Networks_NetIP_UDP)
	r4 := sui.newRule(sg2, sg3, common.Networks_NetIP_TCP)
	sui.syncRules([]*api.Rule{r1, r2, r3, r4}, api.SyncReq_FullSync)

	tests := []struct {
		from, to      string
		shouldBeFound bool
	}{
		{"sg1", "sg2", true},
		{"sg1", "sg3", true},

		{"sg2", "sg1", true},
		{"sg2", "sg3", true},

		{"sg3", "sg1", false},
		{"sg3", "sg2", false},
	}

	req := new(api.GetRulesReq)
	for _, t := range tests {
		req.SgFrom = t.from
		req.SgTo = t.to
		if resp, err := sui.srv.GetRules(sui.ctx, req); !t.shouldBeFound {
			sui.Require().Error(err)
			sui.Require().Equal(codes.NotFound, status.Code(err))
		} else {
			sui.Require().Equal(t.from, resp.GetRules()[0].GetSgFrom())
			sui.Require().Equal(t.to, resp.GetRules()[0].GetSgTo())
		}
	}
}

func (sui *sGroupServiceTests) Test_FindRules() {
	sg1 := sui.newSG("sg1")
	sg2 := sui.newSG("sg2")
	sg3 := sui.newSG("sg3")
	sui.syncSGs([]*api.SecGroup{sg1, sg2, sg3}, api.SyncReq_FullSync)

	r1 := sui.newRule(sg1, sg2, common.Networks_NetIP_TCP)
	r2 := sui.newRule(sg1, sg3, common.Networks_NetIP_UDP)
	r3 := sui.newRule(sg2, sg1, common.Networks_NetIP_TCP)
	r4 := sui.newRule(sg2, sg3, common.Networks_NetIP_UDP)
	sui.syncRules([]*api.Rule{r1, r2, r3, r4}, api.SyncReq_FullSync)

	type sgPair = [2]string
	expect := func(pairs ...string) map[sgPair]bool {
		n := len(pairs)
		if n%2 != 0 {
			panic("odd pairs")
		}
		ret := make(map[sgPair]bool)
		for i := 0; i < n; i += 2 {
			ret[sgPair{pairs[i], pairs[i+1]}] = true
		}
		return ret
	}
	got := func(rr []*api.Rule) map[sgPair]struct{} {
		ret := make(map[sgPair]struct{})
		for _, r := range rr {
			ret[sgPair{r.GetSgFrom(),
				r.GetSgTo()}] = struct{}{}
		}
		return ret
	}
	sl := func(s ...string) []string { return s }
	tests := []struct {
		from []string
		to   []string
		exp  map[sgPair]bool
	}{
		{sl(), sl(), expect("sg1", "sg2", "sg1", "sg3", "sg2", "sg1", "sg2", "sg3")},
		{sl("sg1"), sl(), expect("sg1", "sg2", "sg1", "sg3")},
		{sl(), sl("sg1"), expect("sg2", "sg1")},
		{sl("sg1", "sg2"), sl("sg3"), expect("sg1", "sg3", "sg2", "sg3")},
		{sl("sg3"), sl(), expect()},
	}

	req := new(api.FindRulesReq)
	for _, t := range tests {
		req.SgFrom = t.from
		req.SgTo = t.to
		resp, err := sui.srv.FindRules(sui.ctx, req)
		sui.Require().NoError(err)
		sui.Require().NotNil(resp)
		g := got(resp.GetRules())
		for k := range g {
			ok := t.exp[k]
			sui.Require().True(ok)
			delete(t.exp, k)
		}
		sui.Require().Equal(0, len(t.exp))
	}
}
