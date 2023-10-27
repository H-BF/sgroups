package provider

import (
	"context"
	"net"
	"strings"
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
		Ctx: context.Background(),
	}

	testData.LoadFixture(sui.T(), "sample-acc-test.yaml")

	testData.InitBackend(sui.T(), sui.sgClient)

	initialProto := testData.InitialBackend.Networks.Decode()
	var initialDomain fixtures.DomainRcList[domain.Network]
	fixtures.Backend2Domain(initialProto, &initialDomain)
	initialDict := initialDomain.ToDict()

	resourceTestCase := resource.TestCase{
		ProtoV6ProviderFactories: sui.providerFactories,
	}
	createTest := true
	for tcName, tc := range testData.Cases {
		var expectedDomain, notExpectedDomain fixtures.DomainRcList[domain.Network]
		expectedProto := tc.Expected.Networks.Decode()
		fixtures.Backend2Domain(expectedProto, &expectedDomain)
		notExpectedProto := tc.NotExpeced.Networks.Decode()
		fixtures.Backend2Domain(notExpectedProto, &notExpectedDomain)

		resourceTestCase.Steps = append(resourceTestCase.Steps, resource.TestStep{
			Config: tc.TfConfig,
			PreConfig: func() {
				if createTest {
					expectedDomain.ToDict().Iterate(func(k string, v domain.Network) bool {
						if _, initial := initialDict.Get(k); !initial {
							sui.Require().Nilf(sui.getNetwork(v.Name), "%s : there are network %s already", tcName, k)
						}
						return true
					})
				}
			},
			Check: func(_ *terraform.State) error {
				expectedDomain.ToDict().Iterate(func(k string, v domain.Network) bool {
					network := sui.getNetwork(v.Name)
					sui.Require().NotNilf(network, "%s : network %s not found", tcName, k)
					_, gotNet, _ := net.ParseCIDR(network.GetNetwork().GetCIDR())
					sui.Require().Equalf(v.Net, *gotNet, "%s : network cidr differ", tcName)
					return true
				})

				notExpectedDomain.ToDict().Iterate(func(k string, v domain.Network) bool {
					network := sui.getNetwork(v.Name)
					sui.Require().Nilf(network, "%s : network %s should be deleted", tcName, k)
					return true
				})
				return nil
			},
		})

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

func (sui *networksTests) fixtureTfConfig(f fixtures.NetworksRC) string {
	config := new(strings.Builder)
	sui.Require().NoError(f.TfRcConf(config))
	return config.String()
}
