package provider

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/H-BF/corlib/pkg/slice"
	protos "github.com/H-BF/protos/pkg/api/sgroups"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

func TestAccSgs(t *testing.T) {
	ctx := context.Background()
	rName1 := acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum)
	rName2 := acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum)

	if sg := getSg(ctx, t, rName1); sg != nil {
		t.Errorf("there are sg %s already", rName1)
	}

	if sg := getSg(ctx, t, rName2); sg != nil {
		t.Errorf("there are sg %s already", rName1)
	}

	deleteTestNetworks, err := createTestNetworks(ctx, &testAccSgClient)
	if err != nil {
		t.Errorf("cant create test networks: %s", err.Error())
	}
	defer deleteTestNetworks()

	firstTestData := sgTestData{
		name:          rName1,
		logs:          true,
		trace:         true,
		defaultAction: "DROP",
		network_names: []string{"nw1", "nw2"}}

	secondTestData := sgTestData{
		name:          rName2,
		defaultAction: "ACCEPT",
		network_names: []string{"nw3", "nw4"}}

	thirdTestData := firstTestData
	thirdTestData.logs = false
	thirdTestData.trace = false
	thirdTestData.network_names = []string{"nw1", "nw5"}

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: sgsConfig(firstTestData, secondTestData),
				Check: func(tState *terraform.State) error {
					sg := getSg(ctx, t, firstTestData.name)
					if sg == nil {
						return fmt.Errorf("sg %s not found", firstTestData.name)
					}
					if err := sgAssert(t, sg, firstTestData); err != nil {
						return err
					}

					sg = getSg(ctx, t, secondTestData.name)
					if sg == nil {
						return fmt.Errorf("sg %s not found", secondTestData.name)
					}
					if err := sgAssert(t, sg, secondTestData); err != nil {
						return err
					}

					return nil
				},
			},
			{
				Config: sgsConfig(thirdTestData),
				Check: func(tState *terraform.State) error {
					sg := getSg(ctx, t, thirdTestData.name)
					if sg == nil {
						return fmt.Errorf("sg %s not found", thirdTestData.name)
					}
					if err := sgAssert(t, sg, thirdTestData); err != nil {
						return err
					}

					sg = getSg(ctx, t, secondTestData.name)
					if sg != nil {
						return fmt.Errorf("sg %s should be deleted", secondTestData.name)
					}
					return nil
				},
			},
		},
	})
}

func getSg(ctx context.Context, t *testing.T, sgName string) *protos.SecGroup {
	resp, err := testAccSgClient.ListSecurityGroups(ctx, &protos.ListSecurityGroupsReq{
		SgNames: []string{sgName},
	})
	if err != nil {
		t.Errorf("list sg: %v", err)
	}

	if len(resp.GetGroups()) == 0 {
		return nil
	}

	return resp.GetGroups()[0]
}

func sgAssert(t *testing.T, sg *protos.SecGroup, td sgTestData) error {
	if sg.GetLogs() != td.logs {
		return fmt.Errorf("sg Logs %s differs from configured %s", strconv.FormatBool(sg.GetLogs()), strconv.FormatBool(td.logs))
	}
	if sg.GetTrace() != td.trace {
		return fmt.Errorf("sg Trace %s differs from configured %s", strconv.FormatBool(sg.GetTrace()), strconv.FormatBool(td.trace))
	}
	if sg.GetDefaultAction().String() != td.defaultAction {
		return fmt.Errorf("sg Default Action %s differs from configured %s", sg.GetDefaultAction().String(), td.defaultAction)
	}

	sgNets := sg.GetNetworks()
	sort.Strings(sgNets)
	_ = slice.DedupSlice(&sgNets, func(i, j int) bool {
		return sgNets[i] == sgNets[j]
	})

	tdNets := td.network_names[:]
	sort.Strings(tdNets)
	_ = slice.DedupSlice(&tdNets, func(i, j int) bool {
		return tdNets[i] == tdNets[j]
	})

	if strings.Join(sgNets, ",") != strings.Join(tdNets, ",") {
		return fmt.Errorf("sg Networks %s differs from configured %s", sgNets, td.network_names)
	}

	return nil
}

func sgsConfig(fst testDataItem, others ...testDataItem) string {
	return buildConfig(sgsTemplate, fst, others...)
}
