package internal

import (
	"context"
	"fmt"
	"strings"

	sgroupsAPI "github.com/H-BF/protos/pkg/api/sgroups"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/pkg/errors"
)

// RcSGs -
const RcSGs = SGroupsProvider + "_groups"

/*// resource skeleton
items:
- name: sg1
  networks: "nw1, nw2"
  trace: <true|false>
  logs: <true|false>
  default_action: <DROP|ACCEPT>
- name: sg2
  networks: "nw3"
  trace: <true|false>
  logs: <true|false>
  default_action: <DROP|ACCEPT>
*/

// SGroupsRcSGs SGs resource
func SGroupsRcSGs() *schema.Resource {
	itemRC := SGroupsRcSG()
	itemRC.CreateContext = nil
	itemRC.UpdateContext = nil
	itemRC.CreateContext = nil
	itemRC.DeleteContext = nil
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
				Elem:     itemRC,
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
			items = append(items, protoSG2tf(sg))
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
	da, _ := it[RcLabelDefaultAction].(string)
	x, ok := sgroupsAPI.SecGroup_DefaultAction_value[strings.ToUpper(da)]
	if !ok {
		return "", nil, errors.Errorf("unable to convert '%s' into SG default action", da)
	}
	sg.DefaultAction = sgroupsAPI.SecGroup_DefaultAction(x)
	sg.Trace, _ = it[RcLabelTrace].(bool)
	sg.Logs, _ = it[RcLabelLogs].(bool)
	return sg.Name, &sg, nil
}

func protoSG2tf(sg *sgroupsAPI.SecGroup) map[string]any {
	return map[string]any{
		RcLabelName:          sg.GetName(),
		RcLabelNetworks:      strings.Join(sg.GetNetworks(), ","),
		RcLabelLogs:          sg.GetLogs(),
		RcLabelTrace:         sg.GetTrace(),
		RcLabelDefaultAction: sg.GetDefaultAction().String(),
	}
}
