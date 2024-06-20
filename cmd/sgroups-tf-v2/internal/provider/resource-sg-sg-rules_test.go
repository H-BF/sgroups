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

type sgSgRulesTests struct {
	baseResourceTests
}

func TestAccSgSgRules(t *testing.T) {
	suite.Run(t, new(sgSgRulesTests))
}

func (sui *sgSgRulesTests) TestSgSgRules_Straight() {
	resourceTestCase := sui.testSgSgRulesFromFixtureFilename("data/sg-sg-rules.yaml")
	resource.Test(sui.T(), resourceTestCase)
}

// when to rules map inserted new rule with `ports = []` field
func (sui *sgSgRulesTests) TestSgSgRules_PortsAreEmptyList() {
	resourceTestCase := sui.testSgSgRulesFromFixtureFilename("data/sg-sg-rules_ports-are-empty-list.yaml")
	resource.Test(sui.T(), resourceTestCase)
}

func (sui *sgSgRulesTests) testSgSgRulesFromFixtureFilename(name string) resource.TestCase {
	testData := fixtures.AccTests{Ctx: sui.ctx}
	testData.LoadFixture(sui.T(), name)
	testData.InitBackend(sui.T(), sui.sgClient)
	resourceTestCase := resource.TestCase{
		ProtoV6ProviderFactories: sui.providerFactories,
	}
	for _, tc := range testData.Cases {
		tcName := tc.TestName
		expectedBackend := tc.Expected.SgSgRules.Decode()
		nonExpectedBackend := tc.NonExpected.SgSgRules.Decode()

		resourceTestCase.Steps = append(resourceTestCase.Steps, resource.TestStep{
			Config: sui.providerConfig + "\n" + tc.TfConfig,
			Check: func(_ *terraform.State) error {
				if len(expectedBackend)+len(nonExpectedBackend) > 0 {
					allRules := sui.listAllSgRules()
					var checker fixtures.ExpectationsChecker[protos.SgSgRule, domain.SGRule]
					checker.Init(allRules)

					if !checker.WeExpectFindAll(expectedBackend) {
						return fmt.Errorf("on check '%s' we expect to find all these SgRules[%s] in [%s]",
							tcName, slice2string(expectedBackend...), slice2string(allRules...))
					}

					if !checker.WeDontExpectFindAny(nonExpectedBackend) {
						return fmt.Errorf("on check '%s' we dont expect to find any of SgRules[%s] in [%s]",
							tcName, slice2string(nonExpectedBackend...), slice2string(allRules...))
					}
				}
				return nil
			},
		})
	}

	return resourceTestCase
}

func (sui *sgSgRulesTests) listAllSgRules() []*protos.SgSgRule {
	resp, err := sui.sgClient.FindSgSgRules(sui.ctx, &protos.FindSgSgRulesReq{
		SgFrom: []string{},
		SgTo:   []string{},
	})
	sui.Require().NoError(err)
	return resp.GetRules()
}
