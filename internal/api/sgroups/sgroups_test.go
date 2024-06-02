package sgroups

import (
	"context"
	"net"
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
			m, e := registry.NewMemDB(registry.AllTables())
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
		Name:          name,
		Networks:      nws,
		DefaultAction: api.SecGroup_DROP,
	}
}

func (sui *sGroupServiceTests) newPorts(s, d string) *api.AccPorts {
	return &api.AccPorts{S: s, D: d}
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

func (sui *sGroupServiceTests) newRule(from, to *api.SecGroup, tr common.Networks_NetIP_Transport, ports ...*api.AccPorts) *api.SgSgRule {
	return &api.SgSgRule{
		SgFrom:    from.Name,
		SgTo:      to.Name,
		Transport: tr,
		Ports:     ports,
		Action:    api.RuleAction_ACCEPT,
	}
}

func (sui *sGroupServiceTests) newSgSgRule(
	sgLocal, sg *api.SecGroup,
	transport common.Networks_NetIP_Transport,
	traffic common.Traffic,
	ports ...*api.AccPorts) *api.IESgSgRule {
	return &api.IESgSgRule{
		Transport: transport,
		SG:        sg.Name,
		SgLocal:   sgLocal.Name,
		Traffic:   traffic,
		Ports:     ports,
		Action:    api.RuleAction_DROP,
	}
}

func (sui *sGroupServiceTests) newIESgSgIcmpRule(
	sgLocal, sg *api.SecGroup,
	traffic common.Traffic,
	ipv common.IpAddrFamily,
) *api.IESgSgIcmpRule {
	return &api.IESgSgIcmpRule{
		SG:      sg.Name,
		SgLocal: sgLocal.Name,
		Traffic: traffic,
		ICMP:    &common.ICMP{IPv: ipv},
		Action:  api.RuleAction_DROP,
	}
}

func (sui *sGroupServiceTests) newCidrSgIcmpRule(
	cidr string,
	sg *api.SecGroup,
	traffic common.Traffic,
	ipv common.IpAddrFamily,
) *api.IECidrSgIcmpRule {
	_, _, err := net.ParseCIDR(cidr)
	sui.Require().NoError(err)
	return &api.IECidrSgIcmpRule{
		CIDR:    cidr,
		SG:      sg.GetName(),
		Traffic: traffic,
		ICMP:    &common.ICMP{IPv: ipv},
		Action:  api.RuleAction_ACCEPT,
	}
}

func (sui *sGroupServiceTests) syncRules(rules []*api.SgSgRule, op api.SyncReq_SyncOp) {
	req := api.SyncReq{
		SyncOp: op,
		Subject: &api.SyncReq_SgSgRules{
			SgSgRules: &api.SyncSgSgRules{
				Rules: rules,
			},
		},
	}
	_, err := sui.srv.Sync(sui.ctx, &req)
	sui.Require().NoError(err)
}

func (sui *sGroupServiceTests) syncSgSgRules(rules []*api.IESgSgRule, op api.SyncReq_SyncOp) {
	req := api.SyncReq{
		SyncOp: op,
		Subject: &api.SyncReq_IeSgSgRules{
			IeSgSgRules: &api.SyncIESgSgRules{
				Rules: rules,
			},
		},
	}
	_, err := sui.srv.Sync(sui.ctx, &req)
	sui.Require().NoError(err)
}

func (sui *sGroupServiceTests) syncIESgSgIcmpRules(rules []*api.IESgSgIcmpRule, op api.SyncReq_SyncOp) {
	req := api.SyncReq{
		SyncOp: op,
		Subject: &api.SyncReq_IeSgSgIcmpRules{
			IeSgSgIcmpRules: &api.SyncIESgSgIcmpRules{
				Rules: rules,
			},
		},
	}
	_, err := sui.srv.Sync(sui.ctx, &req)
	sui.Require().NoError(err)
}

func (sui *sGroupServiceTests) syncCidrSgIcmpRules(rules []*api.IECidrSgIcmpRule, op api.SyncReq_SyncOp) {
	req := api.SyncReq{
		SyncOp: op,
		Subject: &api.SyncReq_IeCidrSgIcmpRules{
			IeCidrSgIcmpRules: &api.SyncIECidrSgIcmpRules{
				Rules: rules,
			},
		},
	}
	_, err := sui.srv.Sync(sui.ctx, &req)
	sui.Require().NoError(err)
}

func (sui *sGroupServiceTests) rule2Id(rules ...*api.SgSgRule) []model.SGRuleIdentity {
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

func (sui *sGroupServiceTests) sgSgRule2Id(rules ...*api.IESgSgRule) []model.IESgSgRuleIdentity {
	var ret []model.IESgSgRuleIdentity
	for _, r := range rules {
		var id model.IESgSgRuleIdentity
		id.SgLocal = r.GetSgLocal()
		id.Sg = r.GetSG()
		err := (networkTransport{&id.Transport}).
			from(r.GetTransport())
		sui.Require().NoError(err)
		err = (traffic{&id.Traffic}).from(r.GetTraffic())
		sui.Require().NoError(err)
		ret = append(ret, id)
	}
	return ret
}

func (sui *sGroupServiceTests) ieSgSgIcmpRule2Id(rules ...*api.IESgSgIcmpRule) []model.IESgSgIcmpRuleID {
	var ret []model.IESgSgIcmpRuleID
	for _, r := range rules {
		var id model.IESgSgIcmpRuleID
		id.SgLocal = r.GetSgLocal()
		id.Sg = r.GetSG()
		err := (traffic{&id.Traffic}).from(r.GetTraffic())
		sui.Require().NoError(err)
		ipv := r.GetICMP().GetIPv()
		switch ipv {
		case common.IpAddrFamily_IPv4:
			id.IPv = 4
		case common.IpAddrFamily_IPv6:
			id.IPv = 6
		}
		ret = append(ret, id)
	}
	return ret
}

func (sui *sGroupServiceTests) cidrSgIcmpRule2Id(rules ...*api.IECidrSgIcmpRule) []model.IECidrSgIcmpRuleID {
	var ret []model.IECidrSgIcmpRuleID
	for _, r := range rules {
		var id model.IECidrSgIcmpRuleID
		_, ipnet, err := net.ParseCIDR(r.GetCIDR())
		sui.Require().NoError(err)
		id.CIDR = *ipnet
		id.SG = r.GetSG()
		err = (traffic{&id.Traffic}).from(r.GetTraffic())
		sui.Require().NoError(err)
		ipv := r.GetICMP().GetIPv()
		switch ipv {
		case common.IpAddrFamily_IPv4:
			id.IPv = 4
		case common.IpAddrFamily_IPv6:
			id.IPv = 6
		}
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
	sui.syncRules([]*api.SgSgRule{rule1, rule2}, api.SyncReq_FullSync)

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

	sui.syncRules([]*api.SgSgRule{rule1, rule2}, api.SyncReq_Delete)
	r = sui.reader()
	var cn int
	err = r.ListSGRules(sui.ctx, func(_ model.SGRule) error {
		cn++
		return nil
	}, registry.NoScope)
	sui.Require().NoError(err)
	sui.Require().Equal(0, cn)

	sui.syncRules([]*api.SgSgRule{rule1, rule2}, api.SyncReq_FullSync)
	sui.syncSGs([]*api.SecGroup{sg1}, api.SyncReq_Delete)
	r = sui.reader()
	err = r.ListSGRules(sui.ctx, func(_ model.SGRule) error {
		cn++
		return nil
	}, registry.NoScope)
	sui.Require().NoError(err)
	sui.Require().Equal(0, cn)
}

func (sui *sGroupServiceTests) Test_Sync_SgSgRules() {
	sg1 := sui.newSG("sg1")
	sg2 := sui.newSG("sg2")
	sg3 := sui.newSG("sg3")
	sg4 := sui.newSG("sg4")
	sui.syncSGs([]*api.SecGroup{sg1, sg2, sg3, sg4}, api.SyncReq_FullSync)

	rule1 := sui.newSgSgRule(sg1, sg2, common.Networks_NetIP_TCP, common.Traffic_Egress, sui.newPorts("100-200", "80"))
	rule2 := sui.newSgSgRule(sg3, sg4, common.Networks_NetIP_UDP, common.Traffic_Ingress, sui.newPorts("100-200", "80"))

	sui.syncSgSgRules([]*api.IESgSgRule{rule1, rule2}, api.SyncReq_FullSync)
	r := sui.reader()
	m := make(map[string]bool)
	err := r.ListSgSgRules(sui.ctx, func(rule model.IESgSgRule) error {
		m[rule.ID.IdentityHash()] = true
		return nil
	}, registry.NoScope)
	sui.Require().NoError(err)
	ids := sui.sgSgRule2Id(rule1, rule2)
	for _, x := range ids {
		ok := m[x.IdentityHash()]
		sui.Require().Truef(ok, "required rule '%s'", x)
	}

	sui.syncSgSgRules([]*api.IESgSgRule{rule1, rule2}, api.SyncReq_Delete)
	r = sui.reader()
	var cn int
	err = r.ListSgSgRules(sui.ctx, func(_ model.IESgSgRule) error {
		cn++
		return nil
	}, registry.NoScope)
	sui.Require().NoError(err)
	sui.Require().Equal(0, cn)

	sui.syncSgSgRules([]*api.IESgSgRule{rule1, rule2}, api.SyncReq_FullSync)
	sui.syncSGs([]*api.SecGroup{sg1, sg3}, api.SyncReq_Delete)
	r = sui.reader()
	err = r.ListSgSgRules(sui.ctx, func(_ model.IESgSgRule) error {
		cn++
		return nil
	}, registry.NoScope)
	sui.Require().NoError(err)
	sui.Require().Equal(0, cn)
}

func (sui *sGroupServiceTests) Test_Sync_IESgSgIcmpRules() {
	sg1 := sui.newSG("sg1")
	sg2 := sui.newSG("sg2")
	sg3 := sui.newSG("sg3")
	sg4 := sui.newSG("sg4")
	sui.syncSGs([]*api.SecGroup{sg1, sg2, sg3, sg4}, api.SyncReq_FullSync)

	rule1 := sui.newIESgSgIcmpRule(sg1, sg2, common.Traffic_Egress, common.IpAddrFamily_IPv4)
	rule2 := sui.newIESgSgIcmpRule(sg3, sg4, common.Traffic_Ingress, common.IpAddrFamily_IPv6)

	sui.syncIESgSgIcmpRules([]*api.IESgSgIcmpRule{rule1, rule2}, api.SyncReq_FullSync)
	r := sui.reader()
	m := make(map[string]bool)
	err := r.ListIESgSgIcmpRules(sui.ctx, func(rule model.IESgSgIcmpRule) error {
		m[rule.ID().IdentityHash()] = true
		return nil
	}, registry.NoScope)
	sui.Require().NoError(err)
	ids := sui.ieSgSgIcmpRule2Id(rule1, rule2)
	for _, x := range ids {
		ok := m[x.IdentityHash()]
		sui.Require().Truef(ok, "required rule '%s'", x)
	}

	sui.syncIESgSgIcmpRules([]*api.IESgSgIcmpRule{rule1, rule2}, api.SyncReq_Delete)
	r = sui.reader()
	var cn int
	err = r.ListIESgSgIcmpRules(sui.ctx, func(_ model.IESgSgIcmpRule) error {
		cn++
		return nil
	}, registry.NoScope)
	sui.Require().NoError(err)
	sui.Require().Equal(0, cn)

	sui.syncIESgSgIcmpRules([]*api.IESgSgIcmpRule{rule1, rule2}, api.SyncReq_FullSync)
	sui.syncSGs([]*api.SecGroup{sg1, sg3}, api.SyncReq_Delete)
	r = sui.reader()
	err = r.ListIESgSgIcmpRules(sui.ctx, func(_ model.IESgSgIcmpRule) error {
		cn++
		return nil
	}, registry.NoScope)
	sui.Require().NoError(err)
	sui.Require().Equal(0, cn)
}

func (sui *sGroupServiceTests) Test_Sync_CidrSgIcmpRules() {
	sg1 := sui.newSG("sg1")
	sg2 := sui.newSG("sg2")
	sui.syncSGs([]*api.SecGroup{sg1, sg2}, api.SyncReq_FullSync)

	rule1 := sui.newCidrSgIcmpRule("10.10.10.0/24", sg1, common.Traffic_Egress, common.IpAddrFamily_IPv4)
	rule2 := sui.newCidrSgIcmpRule("2001:db8::/64", sg2, common.Traffic_Ingress, common.IpAddrFamily_IPv6)

	sui.syncCidrSgIcmpRules([]*api.IECidrSgIcmpRule{rule1, rule2}, api.SyncReq_FullSync)
	r := sui.reader()
	m := make(map[string]bool)
	err := r.ListCidrSgIcmpRules(sui.ctx, func(rule model.IECidrSgIcmpRule) error {
		m[rule.ID().IdentityHash()] = true
		return nil
	}, registry.NoScope)
	sui.Require().NoError(err)
	ids := sui.cidrSgIcmpRule2Id(rule1, rule2)
	for _, x := range ids {
		ok := m[x.IdentityHash()]
		sui.Require().Truef(ok, "required rule '%s'", x)
	}

	sui.syncCidrSgIcmpRules([]*api.IECidrSgIcmpRule{rule1, rule2}, api.SyncReq_Delete)
	r = sui.reader()
	var cn int
	err = r.ListCidrSgIcmpRules(sui.ctx, func(_ model.IECidrSgIcmpRule) error {
		cn++
		return nil
	}, registry.NoScope)
	sui.Require().NoError(err)
	sui.Require().Equal(0, cn)

	sui.syncCidrSgIcmpRules([]*api.IECidrSgIcmpRule{rule1, rule2}, api.SyncReq_FullSync)
	sui.syncSGs([]*api.SecGroup{sg1, sg2}, api.SyncReq_Delete)
	r = sui.reader()
	err = r.ListCidrSgIcmpRules(sui.ctx, func(_ model.IECidrSgIcmpRule) error {
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

func (sui *sGroupServiceTests) Test_FindSgSgRules() {
	sg1 := sui.newSG("sg1")
	sg2 := sui.newSG("sg2")
	sg3 := sui.newSG("sg3")
	sui.syncSGs([]*api.SecGroup{sg1, sg2, sg3}, api.SyncReq_FullSync)

	r1 := sui.newRule(sg1, sg2, common.Networks_NetIP_TCP)
	r2 := sui.newRule(sg1, sg3, common.Networks_NetIP_UDP)
	r3 := sui.newRule(sg2, sg1, common.Networks_NetIP_TCP)
	r4 := sui.newRule(sg2, sg3, common.Networks_NetIP_UDP)
	sui.syncRules([]*api.SgSgRule{r1, r2, r3, r4}, api.SyncReq_FullSync)

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
	got := func(rr []*api.SgSgRule) map[sgPair]struct{} {
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

	req := new(api.FindSgSgRulesReq)
	for _, t := range tests {
		req.SgFrom = t.from
		req.SgTo = t.to
		resp, err := sui.srv.FindSgSgRules(sui.ctx, req)
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
