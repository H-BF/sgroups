package internal

import (
	"bytes"
	"context"
	"fmt"
	"sort"
	"strings"

	utils "github.com/H-BF/sgroups/internal/api/sgroups"

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
		Description: fmt.Sprintf("represents SecurityGroups (SG) resource in '%s' provider", SGroupsProvider),
		CreateContext: func(ctx context.Context, rd *schema.ResourceData, i interface{}) diag.Diagnostics {
			return sgsUpd(ctx, rd, i, false)
		},
		UpdateContext: func(ctx context.Context, rd *schema.ResourceData, i interface{}) diag.Diagnostics {
			return sgsUpd(ctx, rd, i, false)
		},
		DeleteContext: sgsDelete,
		ReadContext:   sgsRead,
		Schema: map[string]*schema.Schema{
			RcLabelItems: {
				Optional: true,
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
							DiffSuppressFunc:      sgsSuppressNetworksChanges,
							DiffSuppressOnRefresh: true,
							Description:           "associated set of network(s)",
							Type:                  schema.TypeString,
							Optional:              true,
						},
					},
				},
			},
		},
	}
}

func sgsRead(ctx context.Context, rd *schema.ResourceData, i interface{}) diag.Diagnostics {
	resp, err := i.(SGClient).ListSecurityGroups(ctx, new(sgroupsAPI.ListSecurityGroupsReq))
	if err != nil {
		return diag.FromErr(err)
	}
	var names []string
	var items []any
	buf := bytes.NewBuffer(nil)
	for _, sg := range resp.GetGroups() {
		buf.Reset()
		m := utils.Proto2BriefModelSG(sg)
		for _, n := range m.Networks {
			if buf.Len() > 0 {
				_ = buf.WriteByte(',')
			}
			_, _ = buf.WriteString(n.Name)
		}
		names = append(names, m.Name)
		items = append(items, map[string]any{
			RcLabelName:     m.Name,
			RcLabelNetworks: buf.String(),
		})
	}
	rd.Set(RcLabelItems, items)
	if len(names) == 0 {
		rd.SetId("<none>")
	} else {
		sort.Strings(names)
		rd.SetId(strings.Join(names, ";"))
	}
	return nil
}

func sgsUpd(ctx context.Context, rd *schema.ResourceData, i interface{}, fullSync bool) diag.Diagnostics {
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
	}
	op := sgroupsAPI.SyncReq_Upsert
	if fullSync {
		op = sgroupsAPI.SyncReq_FullSync
	}
	req := sgroupsAPI.SyncReq{
		SyncOp: op,
		Subject: &sgroupsAPI.SyncReq_Groups{
			Groups: &sgroupsAPI.SyncSecurityGroups{
				Groups: sgs,
			},
		},
	}
	if _, err := i.(SGClient).Sync(ctx, &req); err != nil {
		return diag.FromErr(err)
	}
	if len(names) == 0 {
		rd.SetId("<none>")
	} else {
		sort.Strings(names)
		_ = slice.DedupSlice(&names, func(i, j int) bool {
			return names[i] == names[j]
		})
		rd.SetId(strings.Join(names, ";"))
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
	_, err := i.(SGClient).Sync(ctx, &req)
	return diag.FromErr(err)
}

func sgsSuppressNetworksChanges(_, oldValue, newValue string, _ *schema.ResourceData) bool {
	norm := func(s string) string {
		var l []string
		for _, item := range strings.Split(s, ",") {
			if x := strings.TrimSpace(item); len(x) > 0 {
				l = append(l, x)
			}
		}
		sort.Strings(l)
		_ = slice.DedupSlice(&l, func(i, j int) bool {
			return l[i] == l[j]
		})
		return strings.Join(l, ",")
	}
	return norm(oldValue) == norm(newValue)
}
