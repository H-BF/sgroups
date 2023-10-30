package provider

import (
	"fmt"
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
	// os.Setenv("TF_ACC", "1")
	suite.Run(t, new(networksTests))
}

func (sui *networksTests) TestNetworks() {
	testData := fixtures.AccTests{Ctx: sui.ctx}
	testData.LoadFixture(sui.T(), "data/networks.yaml")
	testData.InitBackend(sui.T(), sui.sgClient)
	resourceTestCase := resource.TestCase{
		ProtoV6ProviderFactories: sui.providerFactories,
	}
	for _, tc := range testData.Cases {
		tcName := tc.TestName
		expectedBackendNws := tc.Expected.Networks.Decode()
		nonExpectedBackendNws := tc.NonExpected.Networks.Decode()
		resourceTestCase.Steps = append(resourceTestCase.Steps, resource.TestStep{
			Config: tc.TfConfig,
			Check: func(_ *terraform.State) error {
				if len(expectedBackendNws)+len(nonExpectedBackendNws) > 0 {
					allNws := sui.listAllNetworks()
					var expChecker fixtures.ExpectationsChecker[protos.Network, domain.Network]
					expChecker.Init(allNws)
					if !expChecker.WeExpectFindAll(expectedBackendNws) {
						return fmt.Errorf("on check '%s' we expect to find all Networks[%s] in [%s]",
							tcName, slice2string(expectedBackendNws...),
							slice2string(allNws...))
					}
					if !expChecker.WeDontExpectFindAny(nonExpectedBackendNws) {
						return fmt.Errorf("on check '%s' we dont expect to find any Networks[%s] in [%s]",
							tcName, slice2string(nonExpectedBackendNws...),
							slice2string(allNws...))
					}
				}
				return nil
			},
		})
	}

	resource.Test(sui.T(), resourceTestCase)
}

func (sui *networksTests) listAllNetworks() []*protos.Network {
	resp, err := sui.sgClient.ListNetworks(sui.ctx, &protos.ListNetworksReq{})
	sui.Require().NoError(err)
	return resp.GetNetworks()
}
