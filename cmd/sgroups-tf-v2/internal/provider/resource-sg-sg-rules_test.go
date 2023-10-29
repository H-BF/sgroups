package provider

import (
	"strings"
	"testing"

	protos "github.com/H-BF/protos/pkg/api/sgroups"
	"github.com/H-BF/sgroups/cmd/sgroups-tf-v2/internal/provider/fixtures"
	domain "github.com/H-BF/sgroups/internal/models/sgroups"

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

func (sui *sgSgRulesTests) TestSgsgRules() {
	testData := fixtures.AccTests{
		Ctx: sui.ctx,
	}

	testData.LoadFixture(sui.T(), "sg-sg-rules.yaml")

	testData.InitBackend(sui.T(), sui.sgClient)

	resourceTestCase := resource.TestCase{
		ProtoV6ProviderFactories: sui.providerFactories,
	}
	createTest := true
	for _, tc := range testData.Cases {
		tc := tc
		var expectedDomain, notExpectedDomain fixtures.DomainRcList[domain.SGRule]
		expectedProto := tc.Expected.SgSgRules.Decode()
		fixtures.Backend2Domain(expectedProto, &expectedDomain)
		notExpectedProto := tc.NotExpeced.SgSgRules.Decode()
		fixtures.Backend2Domain(notExpectedProto, &notExpectedDomain)

		step := resource.TestStep{
			Config: tc.TfConfig,
			Check: func(_ *terraform.State) error {
				expectedDomain.ToDict().Iterate(func(k string, v domain.SGRule) bool {
					rule := sui.getSgSgRule(v.ID.SgFrom, v.ID.SgTo)
					sui.Require().NotNilf(rule, "%s : sg-sg rule %s not found", tc.TestName, k)
					sui.sgSgRuleAssert(tc.TestName, rule, v)
					return true
				})

				notExpectedDomain.ToDict().Iterate(func(k string, v domain.SGRule) bool {
					rule := sui.getSgSgRule(v.ID.SgFrom, v.ID.SgTo)
					sui.Require().Nilf(rule, "%s : sg-sg rule %s should be deleted", tc.TestName, k)
					return true
				})
				return nil
			},
		}

		if createTest {
			step.PreConfig = func() {
				expectedDomain.ToDict().Iterate(func(k string, v domain.SGRule) bool {
					sui.Require().Nilf(sui.getSgSgRule(v.ID.SgFrom, v.ID.SgTo),
						"%s : there are sg-sg rule %s already", tc.TestName, k)
					return true
				})
			}
		}

		resourceTestCase.Steps = append(resourceTestCase.Steps, step)

		createTest = false
	}

	resource.Test(sui.T(), resourceTestCase)
}

func (sui *sgSgRulesTests) getSgSgRule(from, to string) *protos.Rule {
	resp, err := sui.sgClient.FindRules(sui.ctx, &protos.FindRulesReq{
		SgFrom: []string{from},
		SgTo:   []string{to},
	})
	sui.Require().NoError(err)

	if len(resp.GetRules()) == 0 {
		return nil
	}

	return resp.GetRules()[0]
}

func (sui *sgSgRulesTests) sgSgRuleAssert(testName string, actual *protos.Rule, expected domain.SGRule) {
	sui.Require().Equalf(expected.ID.Transport.String(), strings.ToLower(actual.GetTransport().String()),
		"%s : sg-sg rule Proto expected to be %s", testName, expected.ID.Transport.String())

	sui.Require().Equalf(expected.ID.SgFrom, actual.GetSgFrom(),
		"%s : sg-sg rule SgFrom expected to be %s", testName, expected.ID.SgFrom)
	sui.Require().Equalf(expected.ID.SgTo, actual.GetSgTo(),
		"%s : sg-sg rule SgTo expected to be %s", testName, expected.ID.SgTo)

	sui.Require().Equalf(expected.Logs, actual.GetLogs(),
		"%s : sg-sg rule Logs expected to be %t", testName, expected.Logs)

	actualPorts := sui.toDomainPorts(actual.GetPorts())
	sui.Require().Truef(domain.AreRulePortsEq(expected.Ports, actualPorts),
		"%s : sg-sg rule Ports expected to be %+v", testName, expected.Ports)
}
