package provider

import (
	"fmt"
	"testing"

	protos "github.com/H-BF/protos/pkg/api/sgroups"
	"github.com/H-BF/sgroups/cmd/sgroups-tf-v2/internal/provider/fixtures"
	domain "github.com/H-BF/sgroups/internal/models/sgroups"
	"github.com/stretchr/testify/suite"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

type sgsTests struct {
	baseResourceTests
}

func TestAccSgs(t *testing.T) {
	suite.Run(t, new(sgsTests))
}

func (sui *sgsTests) TestSgs() {
	testData := fixtures.AccTests{Ctx: sui.ctx}
	testData.LoadFixture(sui.T(), "data/sgs.yaml")
	testData.InitBackend(sui.T(), sui.sgClient)
	resourceTestCase := resource.TestCase{
		ProtoV6ProviderFactories: sui.providerFactories,
	}
	for _, tc := range testData.Cases {
		tcName := tc.TestName
		expectedBackend := tc.Expected.SecGroups.Decode()
		nonExpectedBackend := tc.NonExpected.SecGroups.Decode()

		resourceTestCase.Steps = append(resourceTestCase.Steps, resource.TestStep{
			Config: tc.TfConfig,
			Check: func(_ *terraform.State) error {
				if len(expectedBackend)+len(nonExpectedBackend) > 0 {
					allSgs := sui.listAllSgs()
					var checker fixtures.ExpectationsChecker[protos.SecGroup, domain.SecurityGroup]
					checker.Init(allSgs)

					if !checker.WeExpectFindAll(expectedBackend) {
						return fmt.Errorf("on check '%s' we expect to find all these SecurityGroups[%s] in [%s]",
							tcName, slice2string(expectedBackend...), slice2string(allSgs...))
					}

					if !checker.WeDontExpectFindAny(nonExpectedBackend) {
						return fmt.Errorf("on check '%s' we dont expect to find any of SecurityGroups[%s] in [%s]",
							tcName, slice2string(nonExpectedBackend...), slice2string(allSgs...))
					}
				}
				return nil
			},
		})
	}

	resource.Test(sui.T(), resourceTestCase)
}

func (sui *sgsTests) listAllSgs() []*protos.SecGroup {
	resp, err := sui.sgClient.ListSecurityGroups(sui.ctx, &protos.ListSecurityGroupsReq{SgNames: []string{}})
	sui.Require().NoError(err)
	return resp.GetGroups()
}
