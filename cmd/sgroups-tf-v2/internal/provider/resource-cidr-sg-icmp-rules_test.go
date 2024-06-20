package provider

import (
	"fmt"
	"testing"

	protos "github.com/H-BF/protos/pkg/api/sgroups"
	"github.com/H-BF/sgroups/cmd/sgroups-tf-v2/internal/provider/fixtures"
	domain "github.com/H-BF/sgroups/internal/domains/sgroups"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/stretchr/testify/suite"
)

type cidrSgIcmpRulesTests struct {
	baseResourceTests
}

func TestAccCidrSgIcmpRules(t *testing.T) {
	suite.Run(t, new(cidrSgIcmpRulesTests))
}

func (sui *cidrSgIcmpRulesTests) TestCidrSgIcmpRules_Straight() {
	resourceTestCase := sui.testCidrSgIcmpRulesFromFixtureFilename("data/cidr-sg-icmp-rules.yaml")
	resource.Test(sui.T(), resourceTestCase)
}

func (sui *cidrSgIcmpRulesTests) testCidrSgIcmpRulesFromFixtureFilename(name string) resource.TestCase {
	testData := fixtures.AccTests{Ctx: sui.ctx}
	testData.LoadFixture(sui.T(), name)
	testData.InitBackend(sui.T(), sui.sgClient)
	resourceTestCase := resource.TestCase{
		ProtoV6ProviderFactories: sui.providerFactories,
	}
	for _, tc := range testData.Cases {
		tcName := tc.TestName
		expectedBackend := tc.Expected.IECidrSgIcmpRules.Decode()
		nonExpectedBackend := tc.NonExpected.IECidrSgIcmpRules.Decode()

		resourceTestCase.Steps = append(resourceTestCase.Steps, resource.TestStep{
			Config: sui.providerConfig + "\n" + tc.TfConfig,
			Check: func(_ *terraform.State) error {
				if len(expectedBackend)+len(nonExpectedBackend) > 0 {
					allRules := sui.listAllRules()
					var checker fixtures.ExpectationsChecker[protos.IECidrSgIcmpRule, domain.IECidrSgIcmpRule]
					checker.Init(allRules)

					if !checker.WeExpectFindAll(expectedBackend) {
						return fmt.Errorf("on check '%s' we expect to find all these CidrSgIcmpRules[%s] in [%s]",
							tcName, slice2string(expectedBackend...), slice2string(allRules...))
					}

					if !checker.WeDontExpectFindAny(nonExpectedBackend) {
						return fmt.Errorf("on check '%s' we dont expect to find any of CidrSgIcmpRules[%s] in [%s]",
							tcName, slice2string(nonExpectedBackend...), slice2string(allRules...))
					}
				}
				return nil
			},
		})
	}

	return resourceTestCase
}

func (sui *cidrSgIcmpRulesTests) listAllRules() []*protos.IECidrSgIcmpRule {
	resp, err := sui.sgClient.FindIECidrSgIcmpRules(sui.ctx, &protos.FindIECidrSgIcmpRulesReq{SG: []string{}})
	sui.Require().NoError(err)
	return resp.GetRules()
}
