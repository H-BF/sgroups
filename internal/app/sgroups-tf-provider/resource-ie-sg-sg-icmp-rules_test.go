package provider

import (
	"fmt"
	"testing"

	"github.com/H-BF/sgroups/v2/internal/app/sgroups-tf-provider/fixtures"
	domain "github.com/H-BF/sgroups/v2/internal/domains/sgroups"

	protos "github.com/H-BF/protos/pkg/api/sgroups"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/stretchr/testify/suite"
)

type ieSgSgIcmpRulesTests struct {
	baseResourceTests
}

func TestAccIESgSgIcmpRules(t *testing.T) {
	suite.Run(t, new(ieSgSgIcmpRulesTests))
}

func (sui *ieSgSgIcmpRulesTests) TestIESgSgIcmpRules_Straight() {
	resourceTestCase := sui.testIESgSgIcmpRulesFromFixtureFilename("data/ie-sg-sg-icmp-rules.yaml")
	resource.Test(sui.T(), resourceTestCase)
}

func (sui *ieSgSgIcmpRulesTests) testIESgSgIcmpRulesFromFixtureFilename(name string) resource.TestCase {
	testData := fixtures.AccTests{Ctx: sui.ctx}
	testData.LoadFixture(sui.T(), name)
	testData.InitBackend(sui.T(), sui.sgClient)
	resourceTestCase := resource.TestCase{
		ProtoV6ProviderFactories: sui.providerFactories,
	}
	for _, tc := range testData.Cases {
		tcName := tc.TestName
		expectedBackend := tc.Expected.IESgSgIcmpRules.Decode()
		nonExpectedBackend := tc.NonExpected.IESgSgIcmpRules.Decode()

		resourceTestCase.Steps = append(resourceTestCase.Steps, resource.TestStep{
			Config: sui.providerConfig + "\n" + tc.TfConfig,
			Check: func(_ *terraform.State) error {
				if len(expectedBackend)+len(nonExpectedBackend) > 0 {
					allRules := sui.listAllRules()
					var checker fixtures.ExpectationsChecker[protos.IESgSgIcmpRule, domain.IESgSgIcmpRule]
					checker.Init(allRules)

					if !checker.WeExpectFindAll(expectedBackend) {
						return fmt.Errorf("on check '%s' we expect to find all these IESgSgIcmpRules[%s] in [%s]",
							tcName, slice2string(expectedBackend...), slice2string(allRules...))
					}

					if !checker.WeDontExpectFindAny(nonExpectedBackend) {
						return fmt.Errorf("on check '%s' we dont expect to find any of IESgSgIcmpRules[%s] in [%s]",
							tcName, slice2string(nonExpectedBackend...), slice2string(allRules...))
					}
				}
				return nil
			},
		})
	}

	return resourceTestCase
}

func (sui *ieSgSgIcmpRulesTests) listAllRules() []*protos.IESgSgIcmpRule {
	resp, err := sui.sgClient.FindIESgSgIcmpRules(sui.ctx, &protos.FindIESgSgIcmpRulesReq{
		SgLocal: []string{},
		SG:      []string{},
	})
	sui.Require().NoError(err)
	return resp.GetRules()
}
