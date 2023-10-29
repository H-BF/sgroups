package provider

import (
	"context"
	"net"
	"testing"

	protos "github.com/H-BF/protos/pkg/api/sgroups"
	"github.com/H-BF/sgroups/cmd/sgroups-tf-v2/internal/provider/fixtures"
	domain "github.com/H-BF/sgroups/internal/models/sgroups"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/stretchr/testify/suite"
)

type networksTests struct {
	baseResourceTests
}

func TestAccNetworks(t *testing.T) {
	suite.Run(t, new(networksTests))
}

func (sui *networksTests) TestNetworks() {
	testData := fixtures.AccTests{
		Ctx: sui.ctx,
	}

	testData.LoadFixture(sui.T(), "networks.yaml")

	testData.InitBackend(sui.T(), sui.sgClient)

	initialProto := testData.InitialBackend.Networks.Decode()
	var initialDomain fixtures.DomainRcList[domain.Network]
	fixtures.Backend2Domain(initialProto, &initialDomain)
	initialDict := initialDomain.ToDict()

	resourceTestCase := resource.TestCase{
		ProtoV6ProviderFactories: sui.providerFactories,
	}
	createTest := true
	for _, tc := range testData.Cases {
		tc := tc
		var expectedDomain, notExpectedDomain fixtures.DomainRcList[domain.Network]
		expectedProto := tc.Expected.Networks.Decode()
		fixtures.Backend2Domain(expectedProto, &expectedDomain)
		notExpectedProto := tc.NotExpeced.Networks.Decode()
		fixtures.Backend2Domain(notExpectedProto, &notExpectedDomain)

		step := resource.TestStep{
			Config: tc.TfConfig,
			Check: func(_ *terraform.State) error {
				expectedDomain.ToDict().Iterate(func(k string, v domain.Network) bool {
					network := sui.getNetwork(v.Name)
					sui.Require().NotNilf(network, "%s : network %s not found", tc.TestName, k)
					_, gotNet, _ := net.ParseCIDR(network.GetNetwork().GetCIDR())
					sui.Require().Equalf(v.Net, *gotNet, "%s : network cidr differ", tc.TestName)
					return true
				})

				notExpectedDomain.ToDict().Iterate(func(k string, v domain.Network) bool {
					network := sui.getNetwork(v.Name)
					sui.Require().Nilf(network, "%s : network %s should be deleted", tc.TestName, k)
					return true
				})
				return nil
			},
		}

		if createTest {
			step.PreConfig = func() {
				expectedDomain.ToDict().Iterate(func(k string, v domain.Network) bool {
					if _, initial := initialDict.Get(k); !initial {
						sui.Require().Nilf(sui.getNetwork(v.Name), "%s : there are network %s already", tc.TestName, k)
					}
					return true
				})
			}
		}

		resourceTestCase.Steps = append(resourceTestCase.Steps, step)

		createTest = false
	}

	resource.Test(sui.T(), resourceTestCase)
}

func (sui *networksTests) getNetwork(netName string) *protos.Network {
	resp, err := sui.sgClient.ListNetworks(context.Background(), &protos.ListNetworksReq{
		NeteworkNames: []string{netName},
	})
	sui.Require().NoError(err)

	if len(resp.GetNetworks()) == 0 {
		return nil
	}

	return resp.GetNetworks()[0]
}
