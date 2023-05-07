package internal

import (
	"context"
	"fmt"
	"strings"

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
		CreateContext: sgsC,
		UpdateContext: sgsU,
		DeleteContext: sgsD,
		ReadContext:   sgsR,
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
							DiffSuppressFunc: func(_, oldValue, newValue string, _ *schema.ResourceData) bool {
								a := strings.Join(splitNetNames(oldValue), ",")
								b := strings.Join(splitNetNames(newValue), ",")
								return a == b
							},
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

type crudSGs = listedRcCRUD[sgroupsAPI.SecGroup]

func sgsR(ctx context.Context, rd *schema.ResourceData, i interface{}) diag.Diagnostics {
	var h listedResource[sgroupsAPI.SecGroup]
	h.init("", ";")
	items, _ := rd.Get(RcLabelItems).([]any)
	if err := h.addlist(items, tf2protoSG); err != nil {
		return diag.FromErr(err)
	}
	if len(h.mapped) == 0 {
		rd.SetId(noneID)
		return nil
	}
	var req sgroupsAPI.ListSecurityGroupsReq
	h.walk(func(k string, _ *sgroupsAPI.SecGroup) bool {
		req.SgNames = append(req.SgNames, k)
		h.set(k, nil)
		return true
	})
	resp, err := i.(SGClient).ListSecurityGroups(ctx, &req)
	if err != nil {
		return diag.FromErr(err)
	}
	for _, n := range resp.GetGroups() {
		h.set(n.GetName(), n)
	}
	items = items[:0]
	var e1 error
	h.walk(func(k string, sg *sgroupsAPI.SecGroup) bool {
		if sg != nil {
			o, e := protoSG2tf(sg)
			if e != nil {
				e1 = e
				return false
			}
			items = append(items, o)
		}
		return true
	})
	if e1 != nil {
		return diag.FromErr(e1)
	}
	rd.SetId(h.id(noneID))
	return diag.FromErr(
		rd.Set(RcLabelItems, items),
	)
}

func sgsU(ctx context.Context, rd *schema.ResourceData, i interface{}) diag.Diagnostics {
	crud := crudSGs{tf2proto: tf2protoSG, labelItems: RcLabelItems, client: i.(SGClient)}
	return diag.FromErr(crud.update(ctx, rd))
}

func sgsC(ctx context.Context, rd *schema.ResourceData, i interface{}) diag.Diagnostics {
	crud := crudSGs{tf2proto: tf2protoSG, labelItems: RcLabelItems, client: i.(SGClient)}
	return diag.FromErr(crud.create(ctx, rd))
}

func sgsD(ctx context.Context, rd *schema.ResourceData, i interface{}) diag.Diagnostics {
	crud := crudSGs{tf2proto: tf2protoSG, labelItems: RcLabelItems, client: i.(SGClient)}
	return diag.FromErr(crud.delete(ctx, rd))
}

func tf2protoSG(raw any) (string, *sgroupsAPI.SecGroup, error) {
	it := raw.(map[string]any)
	sg := sgroupsAPI.SecGroup{
		Name: it[RcLabelName].(string),
	}
	nws, _ := it[RcLabelNetworks].(string)
	sg.Networks = splitNetNames(nws)
	return sg.Name, &sg, nil
}

func protoSG2tf(sg *sgroupsAPI.SecGroup) (map[string]any, error) {
	return map[string]any{
		RcLabelName:     sg.GetName(),
		RcLabelNetworks: strings.Join(sg.GetNetworks(), ","),
	}, nil
}
