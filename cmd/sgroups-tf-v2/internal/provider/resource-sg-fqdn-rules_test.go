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

type sgFqdnRulesTests struct {
	baseResourceTests
}

func TestAccSgFqdnRules(t *testing.T) {
	suite.Run(t, new(sgFqdnRulesTests))
}

func (sui *sgFqdnRulesTests) TestSgFqdnRules() {
	testData := fixtures.AccTests{Ctx: sui.ctx}
	testData.LoadFixture(sui.T(), "data/sg-fqdn-rules.yaml")
	testData.InitBackend(sui.T(), sui.sgClient)
	resourceTestCase := resource.TestCase{
		ProtoV6ProviderFactories: sui.providerFactories,
	}
	for _, tc := range testData.Cases {
		tcName := tc.TestName
		expectedBackend := tc.Expected.SgFqdnRules.Decode()
		nonExpectedBackend := tc.NonExpected.SgFqdnRules.Decode()

		resourceTestCase.Steps = append(resourceTestCase.Steps, resource.TestStep{
			Config: tc.TfConfig,
			Check: func(_ *terraform.State) error {
				if len(expectedBackend)+len(nonExpectedBackend) > 0 {
					allRules := sui.listAllFqdnRules()
					var checker fixtures.ExpectationsChecker[protos.FqdnRule, domain.FQDNRule]
					checker.Init(allRules)

					if !checker.WeExpectFindAll(expectedBackend) {
						return fmt.Errorf("on check '%s' we expect to find all these FqdnRules[%s] in [%s]",
							tcName, slice2string(expectedBackend...), slice2string(allRules...))
					}

					if !checker.WeDontExpectFindAny(nonExpectedBackend) {
						return fmt.Errorf("on check '%s' we dont expect to find any of FqdnRules[%s] in [%s]",
							tcName, slice2string(nonExpectedBackend...), slice2string(allRules...))
					}
				}
				return nil
			},
		})
	}

	resource.Test(sui.T(), resourceTestCase)
}

func (sui *sgFqdnRulesTests) listAllFqdnRules() []*protos.FqdnRule {
	resp, err := sui.sgClient.FindFqdnRules(sui.ctx, &protos.FindFqdnRulesReq{SgFrom: []string{}})
	sui.Require().NoError(err)
	return resp.GetRules()
}