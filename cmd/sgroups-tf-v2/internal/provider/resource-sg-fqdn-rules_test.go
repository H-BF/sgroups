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

func TestAccSgFqdnRules(t *testing.T) {
	ctx := context.Background()
	firstTestData := sgFqdnRuleTestData{
		proto: "tcp",
		from:  "sg1",
		to:    "front.example.org",
		logs:  true,
		ports: []accPorts{
			{
				d: "80,443",
				s: "1000-2000",
			},
		},
	}
	secondTestData := sgFqdnRuleTestData{
		proto: "udp",
		from:  "sg3",
		to:    "store.example.org",
		logs:  true,
		ports: []accPorts{
			{
				d: "15000-16000",
				s: "15000-16000",
			},
		},
	}

	changedFirstTestData := firstTestData
	changedFirstTestData.from = "sg2"
	changedFirstTestData.to = "ui.example.org"
	changedFirstTestData.logs = false
	changedFirstTestData.ports = []accPorts{
		{
			d: "22,80,443",
			s: "3000-4000",
		},
	}

	if rule := getSgFqdnRule(ctx, t, firstTestData.from, firstTestData.to); rule != nil {
		t.Errorf("there are sg-fqdn rule %s already", firstTestData.FormatKey())
	}

	if rule := getSgFqdnRule(ctx, t, secondTestData.from, secondTestData.to); rule != nil {
		t.Errorf("there are sg-fqdn rule %s already", secondTestData.FormatKey())
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
				Config: sgFqdnRulesConfig(firstTestData, secondTestData),
				Check: func(s *terraform.State) error {
					rule := getSgFqdnRule(ctx, t, firstTestData.from, firstTestData.to)
					if rule == nil {
						return fmt.Errorf("sg-fqdn rule %s not found", firstTestData.FormatKey())
					}
					if err := sgFqdnRuleAssert(rule, firstTestData); err != nil {
						return err
					}

					rule = getSgFqdnRule(ctx, t, secondTestData.from, secondTestData.to)
					if rule == nil {
						return fmt.Errorf("sg-fqdn rule %s not found", secondTestData.FormatKey())
					}
					if err := sgFqdnRuleAssert(rule, secondTestData); err != nil {
						return err
					}
					return nil
				},
			},
			{
				Config: sgFqdnRulesConfig(changedFirstTestData),
				Check: func(s *terraform.State) error {
					rule := getSgFqdnRule(ctx, t, changedFirstTestData.from, changedFirstTestData.to)
					if rule == nil {
						return fmt.Errorf("sg-fqdn rule %s not found", changedFirstTestData.FormatKey())
					}
					if err := sgFqdnRuleAssert(rule, changedFirstTestData); err != nil {
						return err
					}

					rule = getSgFqdnRule(ctx, t, secondTestData.from, secondTestData.to)
					if rule != nil {
						return fmt.Errorf("sg-fqdn rule %s should be deleted", secondTestData.FormatKey())
					}
					return nil
				},
			},
		},
	})
}

func getSgFqdnRule(ctx context.Context, t *testing.T, from, to string) *protos.FqdnRule {
	resp, err := testAccSgClient.FindFqdnRules(ctx, &protos.FindFqdnRulesReq{
		SgFrom: []string{from},
	})
	if err != nil {
		t.Errorf("find sg-fqdn rule: %v", err)
	}

	if len(resp.GetRules()) == 0 {
		return nil
	}

	if resp.GetRules()[0].GetFQDN() != to {
		return nil
	}

	return resp.GetRules()[0]
}

func sgFqdnRuleAssert(rule *protos.FqdnRule, td sgFqdnRuleTestData) error {
	if rule.GetTransport().String() != strings.ToUpper(td.proto) {
		return fmt.Errorf("sg-fqdn rule Proto %s differs from configured %s", rule.GetTransport().String(), strings.ToUpper(td.proto))
	}
	if rule.GetSgFrom() != td.from {
		return fmt.Errorf("sg-fqdn rule SgFrom %s differs from configured %s", rule.GetSgFrom(), td.from)
	}
	if rule.GetFQDN() != td.to {
		return fmt.Errorf("sg-fqdn rule FQDN %s differs from configured %s", rule.GetFQDN(), td.to)
	}
	if rule.GetLogs() != td.logs {
		return fmt.Errorf("sg-fqdn rule Logs %t differs from configured %t", rule.GetLogs(), td.logs)
	}

	portsAreEq, err := areRulePortsEq(rule.GetPorts(), td.ports)
	if !portsAreEq {
		return fmt.Errorf("sg-fqdn rule Ports %v differs from configured %+v", rule.GetPorts(), td.ports)
	}

	return err
}

func sgFqdnRulesConfig(fst testDataItem, others ...testDataItem) string {
	return buildConfig(sgFqdnRulesTemplate, fst, others...)
}
