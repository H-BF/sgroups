package provider

import (
	"fmt"
	"strings"
	"testing"

	protos "github.com/H-BF/protos/pkg/api/sgroups"
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
	t := sui.T()
	firstTestData := sgSgRuleTestData{
		proto: "tcp",
		from:  "sg1",
		to:    "sg2",
		logs:  true,
		ports: []accPorts{
			{
				d: "80,443",
				s: "1000-2000",
			},
		},
	}
	secondTestData := sgSgRuleTestData{
		proto: "udp",
		from:  "sg3",
		to:    "sg4",
		logs:  true,
		ports: []accPorts{
			{
				d: "15000-16000",
				s: "15000-16000",
			},
		},
	}
	changedFirstTestData := firstTestData
	changedFirstTestData.to = "sg3"
	changedFirstTestData.logs = false
	changedFirstTestData.ports = []accPorts{
		{
			d: "22,80,443",
			s: "3000-4000",
		},
	}

	if rule := sui.getSgSgRule(firstTestData.from, firstTestData.to); rule != nil {
		t.Errorf("there are sg-sg rule %s already", firstTestData.FormatKey())
	}

	if rule := sui.getSgSgRule(secondTestData.from, secondTestData.to); rule != nil {
		t.Errorf("there are sg-sg rule %s already", secondTestData.FormatKey())
	}

	sui.createTestSecGroups()

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: sui.providerFactories,
		Steps: []resource.TestStep{
			{
				Config: sgSgRulesConfig(firstTestData, secondTestData),
				Check: func(s *terraform.State) error {
					rule := sui.getSgSgRule(firstTestData.from, firstTestData.to)
					if rule == nil {
						return fmt.Errorf("sg-sg rule %s not found", firstTestData.FormatKey())
					}
					if err := sui.sgSgRuleAssert(rule, firstTestData); err != nil {
						return err
					}

					rule = sui.getSgSgRule(secondTestData.from, secondTestData.to)
					if rule == nil {
						return fmt.Errorf("sg-sg rule %s not found", secondTestData.FormatKey())
					}
					if err := sui.sgSgRuleAssert(rule, secondTestData); err != nil {
						return err
					}
					return nil
				},
			},
			{
				Config: sgSgRulesConfig(changedFirstTestData),
				Check: func(s *terraform.State) error {
					rule := sui.getSgSgRule(changedFirstTestData.from, changedFirstTestData.to)
					if rule == nil {
						return fmt.Errorf("sg-sg rule %s not found", changedFirstTestData.FormatKey())
					}
					if err := sui.sgSgRuleAssert(rule, changedFirstTestData); err != nil {
						return err
					}

					rule = sui.getSgSgRule(secondTestData.from, secondTestData.to)
					if rule != nil {
						return fmt.Errorf("sg-sg rule %s should be deleted", secondTestData.FormatKey())
					}
					return nil
				},
			},
		},
	})
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

func (sui *sgSgRulesTests) sgSgRuleAssert(rule *protos.Rule, td sgSgRuleTestData) error {
	if rule.GetTransport().String() != strings.ToUpper(td.proto) {
		return fmt.Errorf("sg-sg rule Proto %s differs from configured %s", rule.GetTransport().String(), strings.ToUpper(td.proto))
	}
	if rule.GetSgFrom() != td.from {
		return fmt.Errorf("sg-sg rule SgFrom %s differs from configured %s", rule.GetSgFrom(), td.from)
	}
	if rule.GetSgTo() != td.to {
		return fmt.Errorf("sg-sg rule SgTo %s differs from configured %s", rule.GetSgTo(), td.to)
	}
	if rule.GetLogs() != td.logs {
		return fmt.Errorf("sg-sg rule Logs %t differs from configured %t", rule.GetLogs(), td.logs)
	}

	portsAreEq := sui.areRulePortsEq(rule.GetPorts(), td.ports)
	if !portsAreEq {
		return fmt.Errorf("sg-sg rule Ports %v differs from configured %+v", rule.GetPorts(), td.ports)
	}

	return nil
}

func sgSgRulesConfig(fst testDataItem, others ...testDataItem) string {
	return buildConfig(sgSgRulesTemplate, fst, others...)
}
