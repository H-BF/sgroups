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

type sgFqdnRulesTests struct {
	baseResourceTests
}

func TestAccSgFqdnRules(t *testing.T) {
	suite.Run(t, new(sgFqdnRulesTests))
}

func (sui *sgFqdnRulesTests) TestSgFqdnRules() {
	testData := fixtures.AccTests{
		Ctx: sui.ctx,
	}

	testData.LoadFixture(sui.T(), "sg-fqdn-rules.yaml")

	testData.InitBackend(sui.T(), sui.sgClient)

	resourceTestCase := resource.TestCase{
		ProtoV6ProviderFactories: sui.providerFactories,
	}
	createTest := true
	for _, tc := range testData.Cases {
		tc := tc
		var expectedDomain, notExpectedDomain fixtures.DomainRcList[domain.FQDNRule]
		expectedProto := tc.Expected.SgFqdnRules.Decode()
		fixtures.Backend2Domain(expectedProto, &expectedDomain)
		notExpectedProto := tc.NotExpeced.SgFqdnRules.Decode()
		fixtures.Backend2Domain(notExpectedProto, &notExpectedDomain)

		step := resource.TestStep{
			Config: tc.TfConfig,
			Check: func(_ *terraform.State) error {
				expectedDomain.ToDict().Iterate(func(k string, v domain.FQDNRule) bool {
					rule := sui.getSgFqdnRule(v.ID.SgFrom, v.ID.FqdnTo.String())
					sui.Require().NotNilf(rule, "%s : sg-fqdn rule %s not found", tc.TestName, k)
					sui.sgFqdnRuleAssert(tc.TestName, rule, v)
					return true
				})

				notExpectedDomain.ToDict().Iterate(func(k string, v domain.FQDNRule) bool {
					rule := sui.getSgFqdnRule(v.ID.SgFrom, v.ID.FqdnTo.String())
					sui.Require().Nilf(rule, "%s : sg-fqdn rule %s should be deleted", tc.TestName, k)
					return true
				})
				return nil
			},
		}

		if createTest {
			step.PreConfig = func() {
				expectedDomain.ToDict().Iterate(func(k string, v domain.FQDNRule) bool {
					sui.Require().Nilf(sui.getSgFqdnRule(v.ID.SgFrom, v.ID.FqdnTo.String()),
						"%s : there are sg-fqdn rule %s already", tc.TestName, k)
					return true
				})
			}
		}

		resourceTestCase.Steps = append(resourceTestCase.Steps, step)

		createTest = false
	}

	resource.Test(sui.T(), resourceTestCase)
}

func (sui *sgFqdnRulesTests) getSgFqdnRule(from, to string) *protos.FqdnRule {
	resp, err := sui.sgClient.FindFqdnRules(sui.ctx, &protos.FindFqdnRulesReq{
		SgFrom: []string{from},
	})
	sui.Require().NoError(err)

	if len(resp.GetRules()) == 0 {
		return nil
	}

	if resp.GetRules()[0].GetFQDN() != to {
		return nil
	}

	return resp.GetRules()[0]
}

func (sui *sgFqdnRulesTests) sgFqdnRuleAssert(testName string, actual *protos.FqdnRule, expected domain.FQDNRule) {
	sui.Require().Equalf(expected.ID.Transport.String(), strings.ToLower(actual.GetTransport().String()),
		"%s : sg-fqdn rule Proto expected to be %s", testName, expected.ID.Transport.String())

	sui.Require().Equalf(expected.ID.SgFrom, actual.GetSgFrom(),
		"%s : sg-fqdn rule SgFrom expected to be %s", testName, expected.ID.SgFrom)
	sui.Require().Equalf(expected.ID.FqdnTo.String(), actual.GetFQDN(),
		"%s : sg-fqdn rule FqdnTo expected to be %s", testName, expected.ID.FqdnTo.String())

	sui.Require().Equalf(expected.Logs, actual.GetLogs(),
		"%s : sg-fqdn rule Logs expected to be %t", testName, expected.Logs)

	actualPorts := sui.toDomainPorts(actual.GetPorts())
	sui.Require().Truef(domain.AreRulePortsEq(expected.Ports, actualPorts),
		"%s : sg-fqdn rule Ports expected to be %+v", testName, expected.Ports)
}
