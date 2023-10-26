package provider

// import (
// 	"context"
// 	"fmt"
// 	"sort"
// 	"strings"
// 	"testing"

// 	"github.com/H-BF/corlib/pkg/slice"
// 	protos "github.com/H-BF/protos/pkg/api/sgroups"

// 	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
// 	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
// 	"github.com/hashicorp/terraform-plugin-testing/terraform"
// )

// func TestAccSgs(t *testing.T) {
// 	ctx := context.Background()
// 	rName1 := acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum)
// 	rName2 := acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum)

// 	if sg := getSg(ctx, t, rName1); sg != nil {
// 		t.Errorf("there are sg %s already", rName1)
// 	}

// 	if sg := getSg(ctx, t, rName2); sg != nil {
// 		t.Errorf("there are sg %s already", rName1)
// 	}

// 	deleteTestNetworks, err := createTestNetworks(ctx, &testAccSgClient)
// 	if err != nil {
// 		t.Errorf("cant create test networks: %s", err.Error())
// 	}
// 	defer deleteTestNetworks()

// 	firstTestData := sgTestData{
// 		name:          rName1,
// 		logs:          true,
// 		trace:         true,
// 		defaultAction: "DROP",
// 		network_names: []string{"nw1", "nw2"}}

// 	secondTestData := sgTestData{
// 		name:          rName2,
// 		defaultAction: "ACCEPT",
// 		network_names: []string{"nw3", "nw4"}}

// 	changedFirstTestData := firstTestData
// 	changedFirstTestData.logs = false
// 	changedFirstTestData.trace = false
// 	changedFirstTestData.network_names = []string{"nw1", "nw5"}

// 	resource.Test(t, resource.TestCase{
// 		ProtoV6ProviderFactories: testAccProviders,
// 		Steps: []resource.TestStep{
// 			{
// 				Config: sgsConfig(firstTestData, secondTestData),
// 				Check: func(tState *terraform.State) error {
// 					sg := getSg(ctx, t, firstTestData.name)
// 					if sg == nil {
// 						return fmt.Errorf("sg %s not found", firstTestData.name)
// 					}
// 					if err := sgAssert(sg, firstTestData); err != nil {
// 						return err
// 					}

// 					sg = getSg(ctx, t, secondTestData.name)
// 					if sg == nil {
// 						return fmt.Errorf("sg %s not found", secondTestData.name)
// 					}
// 					if err := sgAssert(sg, secondTestData); err != nil {
// 						return err
// 					}

// 					return nil
// 				},
// 			},
// 			{
// 				Config: sgsConfig(changedFirstTestData),
// 				Check: func(tState *terraform.State) error {
// 					sg := getSg(ctx, t, changedFirstTestData.name)
// 					if sg == nil {
// 						return fmt.Errorf("sg %s not found", changedFirstTestData.name)
// 					}
// 					if err := sgAssert(sg, changedFirstTestData); err != nil {
// 						return err
// 					}

// 					sg = getSg(ctx, t, secondTestData.name)
// 					if sg != nil {
// 						return fmt.Errorf("sg %s should be deleted", secondTestData.name)
// 					}
// 					return nil
// 				},
// 			},
// 		},
// 	})
// }

// func getSg(ctx context.Context, t *testing.T, sgName string) *protos.SecGroup {
// 	resp, err := testAccSgClient.ListSecurityGroups(ctx, &protos.ListSecurityGroupsReq{
// 		SgNames: []string{sgName},
// 	})
// 	if err != nil {
// 		t.Errorf("list sg: %v", err)
// 	}

// 	if len(resp.GetGroups()) == 0 {
// 		return nil
// 	}

// 	return resp.GetGroups()[0]
// }

// func sgAssert(sg *protos.SecGroup, td sgTestData) error {
// 	if sg.GetLogs() != td.logs {
// 		return fmt.Errorf("sg Logs %t differs from configured %t", sg.GetLogs(), td.logs)
// 	}
// 	if sg.GetTrace() != td.trace {
// 		return fmt.Errorf("sg Trace %t differs from configured %t", sg.GetTrace(), td.trace)
// 	}
// 	if sg.GetDefaultAction().String() != td.defaultAction {
// 		return fmt.Errorf("sg Default Action %s differs from configured %s",
// 			sg.GetDefaultAction().String(), td.defaultAction)
// 	}

// 	sgNets := sg.GetNetworks()
// 	sort.Strings(sgNets)
// 	_ = slice.DedupSlice(&sgNets, func(i, j int) bool {
// 		return sgNets[i] == sgNets[j]
// 	})

// 	tdNets := td.network_names[:]
// 	sort.Strings(tdNets)
// 	_ = slice.DedupSlice(&tdNets, func(i, j int) bool {
// 		return tdNets[i] == tdNets[j]
// 	})

// 	if strings.Join(sgNets, ",") != strings.Join(tdNets, ",") {
// 		return fmt.Errorf("sg Networks %s differs from configured %s",
// 			sgNets, td.network_names)
// 	}

// 	return nil
// }

// func sgsConfig(fst testDataItem, others ...testDataItem) string {
// 	return buildConfig(sgsTemplate, fst, others...)
// }
