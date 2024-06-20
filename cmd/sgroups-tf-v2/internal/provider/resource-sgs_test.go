package provider

import (
	"fmt"
	"testing"

	"github.com/H-BF/sgroups/cmd/sgroups-tf-v2/internal/provider/fixtures"
	domain "github.com/H-BF/sgroups/internal/domains/sgroups"

	protos "github.com/H-BF/protos/pkg/api/sgroups"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/stretchr/testify/suite"
)

type sgsTests struct {
	baseResourceTests
}

func TestAccSgs(t *testing.T) {
	suite.Run(t, new(sgsTests))
}

func (sui *sgsTests) TestSgs_Straight() {
	resourceTestCase := sui.makeTestSgsFromFixtureFilename("data/sgs.yaml")
	resource.Test(sui.T(), resourceTestCase)
}

func (sui *sgsTests) TestSgs_SWARM_190() {
	resourceTestCase := sui.makeTestSgsFromFixtureFilename("data/sgs-SWARM-190.yaml")
	resource.Test(sui.T(), resourceTestCase)
}

func (sui *sgsTests) makeTestSgsFromFixtureFilename(name string) resource.TestCase {
	testData := fixtures.AccTests{Ctx: sui.ctx}
	testData.LoadFixture(sui.T(), name)
	testData.InitBackend(sui.T(), sui.sgClient)
	resourceTestCase := resource.TestCase{
		ProtoV6ProviderFactories: sui.providerFactories,
	}
	for _, tc := range testData.Cases {
		tcName := tc.TestName
		expectedBackendGroups := tc.Expected.SecGroups.Decode()
		nonExpectedBackendGroups := tc.NonExpected.SecGroups.Decode()
		expectedBackendIcmps := tc.Expected.SgIcmpRules.Decode()
		nonExpectedBackendIcmps := tc.NonExpected.SgIcmpRules.Decode()

		resourceTestCase.Steps = append(resourceTestCase.Steps, resource.TestStep{
			Config: sui.providerConfig + "\n" + tc.TfConfig,
			Check: func(_ *terraform.State) error {
				if len(expectedBackendGroups)+len(nonExpectedBackendGroups) > 0 {
					allSgs := sui.listAllSgs()
					var groupsChecker fixtures.ExpectationsChecker[protos.SecGroup, domain.SecurityGroup]
					groupsChecker.Init(allSgs)

					if !groupsChecker.WeExpectFindAll(expectedBackendGroups) {
						return fmt.Errorf("on check '%s' we expect to find all these SecurityGroups[%s] in [%s]",
							tcName, slice2string(expectedBackendGroups...), slice2string(allSgs...))
					}
					if !groupsChecker.WeDontExpectFindAny(nonExpectedBackendGroups) {
						return fmt.Errorf("on check '%s' we dont expect to find any of SecurityGroups[%s] in [%s]",
							tcName, slice2string(nonExpectedBackendGroups...), slice2string(allSgs...))
					}

					// check for sub resource: SgIcmpRules
					allIcmps := sui.listAllSgIcmpRules()
					var icmpsChecker fixtures.ExpectationsChecker[protos.SgIcmpRule, domain.SgIcmpRule]
					icmpsChecker.Init(allIcmps)
					if len(expectedBackendIcmps) > 0 && !icmpsChecker.WeExpectFindAll(expectedBackendIcmps) {
						return fmt.Errorf("on check '%s' we expect to find all these SgIcmpRules[%s] in [%s]",
							tcName, slice2string(expectedBackendIcmps...), slice2string(allIcmps...))
					}
					if !icmpsChecker.WeDontExpectFindAny(nonExpectedBackendIcmps) {
						return fmt.Errorf("on check '%s' we dont expect to find any of SgIcmpRules[%s] in [%s]",
							tcName, slice2string(nonExpectedBackendIcmps...), slice2string(allIcmps...))
					}

				}
				return nil
			},
		})
	}

	return resourceTestCase
}

func (sui *sgsTests) listAllSgs() []*protos.SecGroup {
	resp, err := sui.sgClient.ListSecurityGroups(sui.ctx, &protos.ListSecurityGroupsReq{SgNames: []string{}})
	sui.Require().NoError(err)
	return resp.GetGroups()
}

func (sui *sgsTests) listAllSgIcmpRules() []*protos.SgIcmpRule {
	resp, err := sui.sgClient.FindSgIcmpRules(sui.ctx, &protos.FindSgIcmpRulesReq{})
	sui.Require().NoError(err)
	return resp.GetRules()
}
