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

type sgSgIcmpRulesTests struct {
	baseResourceTests
}

func TestAccSgSgIcmpRules(t *testing.T) {
	suite.Run(t, new(sgSgIcmpRulesTests))
}

func (sui *sgSgIcmpRulesTests) TestSgSgIcmpRules() {
	testData := fixtures.AccTests{Ctx: sui.ctx}
	testData.LoadFixture(sui.T(), "data/sg-sg-icmp-rules.yaml")
	testData.InitBackend(sui.T(), sui.sgClient)
	resourceTestCase := resource.TestCase{
		ProtoV6ProviderFactories: sui.providerFactories,
	}
	for _, tc := range testData.Cases {
		tcName := tc.TestName
		expectedBackend := tc.Expected.SgSgIcmpRules.Decode()
		nonExpectedBackend := tc.NonExpected.SgSgIcmpRules.Decode()

		resourceTestCase.Steps = append(resourceTestCase.Steps, resource.TestStep{
			Config: sui.providerConfig + "\n" + tc.TfConfig,
			Check: func(_ *terraform.State) error {
				if len(expectedBackend)+len(nonExpectedBackend) > 0 {
					allRules := sui.listAllSgSgIcmpRules()
					var checker fixtures.ExpectationsChecker[protos.SgSgIcmpRule, domain.SgSgIcmpRule]
					checker.Init(allRules)

					if !checker.WeExpectFindAll(expectedBackend) {
						return fmt.Errorf("on check '%s' we expect to find all these SgSgIcmpRules[%s] in [%s]",
							tcName, slice2string(expectedBackend...), slice2string(allRules...))
					}

					if !checker.WeDontExpectFindAny(nonExpectedBackend) {
						return fmt.Errorf("on check '%s' we dont expect to find any of SgSgIcmpRules[%s] in [%s]",
							tcName, slice2string(nonExpectedBackend...), slice2string(allRules...))
					}
				}
				return nil
			},
		})
	}

	resource.Test(sui.T(), resourceTestCase)
}

func (sui *sgSgIcmpRulesTests) listAllSgSgIcmpRules() []*protos.SgSgIcmpRule {
	resp, err := sui.sgClient.FindSgSgIcmpRules(sui.ctx, &protos.FindSgSgIcmpRulesReq{
		SgFrom: []string{},
		SgTo:   []string{},
	})
	sui.Require().NoError(err)
	return resp.GetRules()
}
