package internal

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/H-BF/corlib/pkg/slice"
	sgroupsAPI "github.com/H-BF/protos/pkg/api/sgroups"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// RcLabelSGs -
const RcLabelSGs = "sec-groups"

/*// resource skeleton
items:
- name: sg1
  networks:
  - name: nw1
  - name: nw2
- name: sg2
  networks:
  - name: nw3
  - name: nw4
*/

// SGroupsRcSGs SGs resource
func SGroupsRcSGs() *schema.Resource {
	return &schema.Resource{
		Description:   fmt.Sprintf("represents SecurityGroups (SG) resource in '%s' provider", SGroupsProvider),
		CreateContext: sgsUpsert,
		DeleteContext: sgsDelete,
		Schema: map[string]*schema.Schema{
			RcLabelItems: {
				Type: schema.TypeList,
				Elem: &schema.Resource{
					Description: "SecurityGroup element",
					Schema: map[string]*schema.Schema{
						RcLabelName: {
							Description: "SecurityGroup name",
							Type:        schema.TypeString,
							Required:    true,
						},
						RcLabelNetworks: {
							Description: "associated set of network(s)",
							Type:        schema.TypeList,
							Required:    false,
							Elem: &schema.Resource{
								Description: "network item",
								Schema: map[string]*schema.Schema{
									RcLabelName: {
										Description: "network name",
										Type:        schema.TypeString,
										Required:    true,
									},
								},
							},
						},
					},
				},
			},
		},
	}
}

func sgsUpsert(ctx context.Context, rd *schema.ResourceData, i interface{}) diag.Diagnostics {
	var sgs []*sgroupsAPI.SecGroup
	var names []string
	if raw, ok := rd.GetOk(RcLabelItems); ok {
		items := raw.([]interface{})
		for _, item := range items {
			it := item.(map[string]interface{})
			sg := sgroupsAPI.SecGroup{
				Name: it[RcLabelName].(string),
			}
			names = append(names, sg.Name)
			if raw, ok := it[RcLabelNetworks]; ok {
				for _, nwItem := range raw.([]interface{}) {
					nw := nwItem.(map[string]interface{})
					sg.Networks = append(sg.Networks,
						&sgroupsAPI.Network{
							Name: nw[RcLabelName].(string),
						},
					)
				}
			}
			sgs = append(sgs, &sg)
		}
		sort.Strings(names)
		_ = slice.DedupSlice(&names, func(i, j int) bool {
			return names[i] == names[j]
		})
	}
	req := sgroupsAPI.SyncReq{
		SyncOp: sgroupsAPI.SyncReq_Upsert,
		Subject: &sgroupsAPI.SyncReq_Groups{
			Groups: &sgroupsAPI.SyncSecurityGroups{
				Groups: sgs,
			},
		},
	}
	c := i.(SGClient)
	if _, err := c.Sync(ctx, &req); err != nil {
		return diag.FromErr(err)
	}
	if len(names) > 0 {
		rd.SetId(strings.Join(names, ";"))
	} else {
		rd.SetId("<none>")
	}
	return nil
}

func sgsDelete(ctx context.Context, rd *schema.ResourceData, i interface{}) diag.Diagnostics {
	raw, ok := rd.GetOk(RcLabelItems)
	if !ok {
		return nil
	}
	items := raw.([]interface{})
	if len(items) == 0 {
		return nil
	}
	var sgs []*sgroupsAPI.SecGroup
	for _, item := range items {
		it := item.(map[string]interface{})
		sg := sgroupsAPI.SecGroup{
			Name: it[RcLabelName].(string),
		}
		sgs = append(sgs, &sg)
	}
	req := sgroupsAPI.SyncReq{
		SyncOp: sgroupsAPI.SyncReq_Delete,
		Subject: &sgroupsAPI.SyncReq_Groups{
			Groups: &sgroupsAPI.SyncSecurityGroups{
				Groups: sgs,
			},
		},
	}
	c := i.(SGClient)
	_, err := c.Sync(ctx, &req)
	return diag.FromErr(err)
}
