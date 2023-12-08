package fixtures

import (
	"context"
	"net"
	"sort"
	"testing"

	domain "github.com/H-BF/sgroups/internal/models/sgroups"

	"github.com/stretchr/testify/require"
)

func Test_Load_AccTests(t *testing.T) {
	tc := AccTests{
		Ctx: context.Background(),
	}
	tc.LoadFixture(t, "sample-acc-test.yaml")
	pp := tc.InitialBackend.Networks.Decode()
	var dd DomainRcList[domain.Network]
	Backend2Domain(pp, &dd)
	di := dd.ToDict()

	var initialBackendNames []string
	for _, it := range di.Items() {
		initialBackendNames = append(initialBackendNames, it.V.Name)
	}

	sort.Strings(initialBackendNames)
	require.Equal(t, []string{"net1", "net2"}, initialBackendNames)
}

func Test_ExtractKey(t *testing.T) {
	var (
		network    domain.Network
		sg         domain.SecurityGroup
		fqdnRule   domain.FQDNRule
		sgRule     domain.SGRule
		sgIcmpRule domain.SgSgIcmpRule
		cidrRule   domain.CidrSgRule
	)
	network.Name = "123"
	require.Equal(t, network.Name, extractKey(network))

	sg.Name = "sg1"
	require.Equal(t, sg.Name, extractKey(sg))

	fqdnRule.ID = domain.FQDNRuleIdentity{
		Transport: 0,
		SgFrom:    "sg1",
		FqdnTo:    "example.org",
	}
	require.Equal(t, "tcp:sg(sg1)fqdn(example.org)", extractKey(fqdnRule))

	sgRule.ID = domain.SGRuleIdentity{
		Transport: 0,
		SgFrom:    "a",
		SgTo:      "b",
	}
	require.Equal(t, "tcp:sg(a)sg(b)", extractKey(sgRule))

	sgIcmpRule.Icmp.IPv = 4
	sgIcmpRule.SgFrom = "a"
	sgIcmpRule.SgTo = "b"

	require.Equal(t, "sg(a)sg(b)icmp4", extractKey(sgIcmpRule))

	_, ipnet, _ := net.ParseCIDR("192.168.1.1/24")
	cidrRule.ID = domain.CidrSgRuleIdenity{
		Transport: 0,
		Traffic:   1,
		SG:        "sg1",
		CIDR:      *ipnet,
	}

	require.Equal(t, "tcp:cidr(192.168.1.0/24)sg(sg1)ingress", extractKey(cidrRule))
}
