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

// RcSGs -
const RcSGs = SGroupsProvider + "_groups"

/*// resource skeleton
items:
- name: sg1
  networks: "nw1, nw2"
- name: sg2
  networks: "nw3"
*/

// SGroupsRcSGs SGs resource
func SGroupsRcSGs() *schema.Resource {
	return &schema.Resource{
		Description:   fmt.Sprintf("represents SecurityGroups (SG) resource in '%s' provider", SGroupsProvider),
		CreateContext: sgsUpsert,
		DeleteContext: sgsDelete,
		ReadContext: func(ctx context.Context, rd *schema.ResourceData, i interface{}) diag.Diagnostics {
			return nil //TODO: Should implement
		},
		Schema: map[string]*schema.Schema{
			RcLabelItems: {
				Optional: true,
				ForceNew: true,
				Type:     schema.TypeList,
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
							Type:        schema.TypeString,
							Optional:    true,
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
				nwNames := strings.Split(raw.(string), ",")
				for i := range nwNames {
					if nwName := strings.TrimSpace(nwNames[i]); len(nwName) > 0 {
						sg.Networks = append(sg.Networks,
							&sgroupsAPI.Network{
								Name: nwName,
							})
					}
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
