package provider

import (
	"fmt"
	"testing"

	"github.com/H-BF/sgroups/internal/app/sgroups-tf-provider/fixtures"
	domain "github.com/H-BF/sgroups/internal/domains/sgroups"

	protos "github.com/H-BF/protos/pkg/api/sgroups"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/stretchr/testify/suite"
)

type cidrRulesTests struct {
	baseResourceTests
}

func TestAccCidrRules(t *testing.T) {
	suite.Run(t, new(cidrRulesTests))
}

func (sui *cidrRulesTests) TestCidrRules_Straight() {
	resourceTestCase := sui.testCidrRulesFromFixtureFilename("data/cidr-sg-rules.yaml")
	resource.Test(sui.T(), resourceTestCase)
}

func (sui *cidrRulesTests) testCidrRulesFromFixtureFilename(name string) resource.TestCase {
	testData := fixtures.AccTests{Ctx: sui.ctx}
	testData.LoadFixture(sui.T(), name)
	testData.InitBackend(sui.T(), sui.sgClient)
	resourceTestCase := resource.TestCase{
		ProtoV6ProviderFactories: sui.providerFactories,
	}
	for _, tc := range testData.Cases {
		tcName := tc.TestName
		expectedBackend := tc.Expected.IECidrSgRules.Decode()
		nonExpectedBackend := tc.NonExpected.IECidrSgRules.Decode()

		resourceTestCase.Steps = append(resourceTestCase.Steps, resource.TestStep{
			Config: sui.providerConfig + "\n" + tc.TfConfig,
			Check: func(_ *terraform.State) error {
				if len(expectedBackend)+len(nonExpectedBackend) > 0 {
					allRules := sui.listAllIECidrRules()
					var checker fixtures.ExpectationsChecker[protos.IECidrSgRule, domain.IECidrSgRule]
					checker.Init(allRules)

					if !checker.WeExpectFindAll(expectedBackend) {
						return fmt.Errorf("on check '%s' we expect to find all these CidrSgRules[%s] in [%s]",
							tcName, slice2string(expectedBackend...), slice2string(allRules...))
					}

					if !checker.WeDontExpectFindAny(nonExpectedBackend) {
						return fmt.Errorf("on check '%s' we dont expect to find any of CidrSgRules[%s] in [%s]",
							tcName, slice2string(nonExpectedBackend...), slice2string(allRules...))
					}
				}
				return nil
			},
		})
	}

	return resourceTestCase
}

func (sui *cidrRulesTests) listAllIECidrRules() []*protos.IECidrSgRule {
	resp, err := sui.sgClient.FindIECidrSgRules(sui.ctx, &protos.FindIECidrSgRulesReq{SG: []string{}})
	sui.Require().NoError(err)
	return resp.GetRules()
}
