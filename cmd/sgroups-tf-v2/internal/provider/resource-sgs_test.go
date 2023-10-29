package provider

import (
	"sort"
	"strings"
	"testing"

	"github.com/H-BF/corlib/pkg/slice"
	protos "github.com/H-BF/protos/pkg/api/sgroups"
	"github.com/H-BF/sgroups/cmd/sgroups-tf-v2/internal/provider/fixtures"
	domain "github.com/H-BF/sgroups/internal/models/sgroups"
	"github.com/stretchr/testify/suite"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

type sgsTests struct {
	baseResourceTests
}

func TestAccSgs(t *testing.T) {
	suite.Run(t, new(sgsTests))
}

func (sui *sgsTests) TestSgs() {
	testData := fixtures.AccTests{
		Ctx: sui.ctx,
	}

	testData.LoadFixture(sui.T(), "data/sgs.yaml")

	testData.InitBackend(sui.T(), sui.sgClient)

	resourceTestCase := resource.TestCase{
		ProtoV6ProviderFactories: sui.providerFactories,
	}
	createTest := true
	for _, tc := range testData.Cases {
		tc := tc
		var expectedDomain, notExpectedDomain fixtures.DomainRcList[domain.SecurityGroup]
		expectedProto := tc.Expected.SecGroups.Decode()
		fixtures.Backend2Domain(expectedProto, &expectedDomain)
		notExpectedProto := tc.NonExpected.SecGroups.Decode()
		fixtures.Backend2Domain(notExpectedProto, &notExpectedDomain)

		step := resource.TestStep{
			Config: tc.TfConfig,
			Check: func(_ *terraform.State) error {
				expectedDomain.ToDict().Iterate(func(k string, v domain.SecurityGroup) bool {
					sg := sui.getSg(v.Name)
					sui.Require().NotNilf(sg, "%s : sg %s not found", tc.TestName, k)
					sui.sgAssert(tc.TestName, sg, v)
					return true
				})

				notExpectedDomain.ToDict().Iterate((func(k string, v domain.SecurityGroup) bool {
					sg := sui.getSg(v.Name)
					sui.Require().Nilf(sg, "%s : sg %s should be deleted", tc.TestName, k)
					return true
				}))
				return nil
			},
		}

		if createTest {
			step.PreConfig = func() {
				expectedDomain.ToDict().Iterate(func(k string, v domain.SecurityGroup) bool {
					sui.Require().Nilf(sui.getSg(v.Name), "%s : there are sg %s already", tc.TestName, k)
					return true
				})
			}
		}

		resourceTestCase.Steps = append(resourceTestCase.Steps, step)

		createTest = false
	}

	resource.Test(sui.T(), resourceTestCase)
}

func (sui *sgsTests) getSg(sgName string) *protos.SecGroup {
	resp, err := sui.sgClient.ListSecurityGroups(sui.ctx, &protos.ListSecurityGroupsReq{
		SgNames: []string{sgName},
	})
	sui.Require().NoError(err)

	if len(resp.GetGroups()) == 0 {
		return nil
	}

	return resp.GetGroups()[0]
}

func (sui *sgsTests) sgAssert(testName string, actual *protos.SecGroup, expected domain.SecurityGroup) {
	sui.Require().Equalf(expected.Logs, actual.GetLogs(),
		"%s : sg Logs expected to be %t", testName, expected.Logs)
	sui.Require().Equalf(expected.Trace, actual.GetTrace(),
		"%s : sg Trace expected to be %t", testName, expected.Trace)

	sui.Require().Equalf(expected.DefaultAction.String(), strings.ToLower(actual.GetDefaultAction().String()),
		"%s : sg Default Action expected to be %d", testName, expected.DefaultAction.String())

	actualNets := actual.GetNetworks()
	sort.Strings(actualNets)
	_ = slice.DedupSlice(&actualNets, func(i, j int) bool {
		return actualNets[i] == actualNets[j]
	})

	expectedNets := expected.Networks[:]
	sort.Strings(expectedNets)
	_ = slice.DedupSlice(&expectedNets, func(i, j int) bool {
		return expectedNets[i] == expectedNets[j]
	})

	sui.Require().Equalf(strings.Join(expectedNets, ","), strings.Join(actualNets, ","),
		"%s : sg Networks expected to be %v", testName, expected.Networks)
}
