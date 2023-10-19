package provider

import (
	"context"
	"fmt"
	"strings"
	"testing"

	protos "github.com/H-BF/protos/pkg/api/sgroups"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

func TestAccSgSgRules(t *testing.T) {
	ctx := context.Background()
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

	if rule := getSgSgRule(ctx, t, firstTestData.from, firstTestData.to); rule != nil {
		t.Errorf("there are sg-sg rule %s already", firstTestData.FormatKey())
	}

	if rule := getSgSgRule(ctx, t, secondTestData.from, secondTestData.to); rule != nil {
		t.Errorf("there are sg-sg rule %s already", secondTestData.FormatKey())
	}

	deleteTestSgs, err := createTestSecGroups(ctx, &testAccSgClient)
	if err != nil {
		t.Errorf("cant create test sgs: %s", err.Error())
	}
	defer deleteTestSgs()

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: sgSgRulesConfig(firstTestData, secondTestData),
				Check: func(s *terraform.State) error {
					rule := getSgSgRule(ctx, t, firstTestData.from, firstTestData.to)
					if rule == nil {
						return fmt.Errorf("sg-sg rule %s not found", firstTestData.FormatKey())
					}
					if err := sgSgRuleAssert(rule, firstTestData); err != nil {
						return err
					}

					rule = getSgSgRule(ctx, t, secondTestData.from, secondTestData.to)
					if rule == nil {
						return fmt.Errorf("sg-sg rule %s not found", secondTestData.FormatKey())
					}
					if err := sgSgRuleAssert(rule, secondTestData); err != nil {
						return err
					}
					return nil
				},
			},
			{
				Config: sgSgRulesConfig(changedFirstTestData),
				Check: func(s *terraform.State) error {
					rule := getSgSgRule(ctx, t, changedFirstTestData.from, changedFirstTestData.to)
					if rule == nil {
						return fmt.Errorf("sg-sg rule %s not found", changedFirstTestData.FormatKey())
					}
					if err := sgSgRuleAssert(rule, changedFirstTestData); err != nil {
						return err
					}

					rule = getSgSgRule(ctx, t, secondTestData.from, secondTestData.to)
					if rule != nil {
						return fmt.Errorf("sg-sg rule %s should be deleted", secondTestData.FormatKey())
					}
					return nil
				},
			},
		},
	})
}

func getSgSgRule(ctx context.Context, t *testing.T, from, to string) *protos.Rule {
	resp, err := testAccSgClient.FindRules(ctx, &protos.FindRulesReq{
		SgFrom: []string{from},
		SgTo:   []string{to},
	})
	if err != nil {
		t.Errorf("find sg-sg rule: %v", err)
	}

	if len(resp.GetRules()) == 0 {
		return nil
	}

	return resp.GetRules()[0]
}

func sgSgRuleAssert(rule *protos.Rule, td sgSgRuleTestData) error {
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

	portsAreEq, err := areRulePortsEq(rule.GetPorts(), td.ports)
	if !portsAreEq {
		return fmt.Errorf("sg-sg rule Ports %v differs from configured %+v", rule.GetPorts(), td.ports)
	}

	return err
}

func sgSgRulesConfig(fst testDataItem, others ...testDataItem) string {
	return buildConfig(sgSgRulesTemplate, fst, others...)
}
