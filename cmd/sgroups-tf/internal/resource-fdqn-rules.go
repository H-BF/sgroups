package internal

import (
	"context"
	"fmt"
	"strings"

	sgroupsAPI "github.com/H-BF/protos/pkg/api/sgroups"
	utils "github.com/H-BF/sgroups/internal/api/sgroups"
	model "github.com/H-BF/sgroups/internal/models/sgroups"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

/*// resource skeleton
items:
- proto: TCP|UDP
  sg_from: sg1
  fdqn: aws.com
  logs: <true|false>
  ports:
  - s: 10
    d: 200-210
  - s: 100-110
    d: 100
*/

// RcFdqnRules -
const RcFdqnRules = SGroupsProvider + "_fdqn_rules"

// SGroupsRcFdqnRules -
func SGroupsRcFdqnRules() *schema.Resource {
	itemRC := SGroupsRcFdqnRule()
	itemRC.CreateContext = nil
	itemRC.ReadContext = nil
	itemRC.UpdateContext = nil
	itemRC.DeleteContext = nil
	return &schema.Resource{
		Description:   fmt.Sprintf("represents FDQN rules resource in '%s' provider", SGroupsProvider),
		CreateContext: fdqnRulesC,
		ReadContext:   fdqnRulesR,
		UpdateContext: fdqnRulesU,
		DeleteContext: fdqnRulesD,
		Schema: map[string]*schema.Schema{
			RcLabelItems: {
				Optional:    true,
				Description: "FDQN rules list",
				Type:        schema.TypeList,
				Elem:        itemRC,
			},
		},
	}
}

func fdqnRulesR(ctx context.Context, rd *schema.ResourceData, i interface{}) diag.Diagnostics {
	items, _ := rd.Get(RcLabelItems).([]any)
	var h listedResource[sgroupsAPI.FdqnRule]
	h.init("", ";")
	if err := h.addlist(items, tf2protoFdqnRule); err != nil {
		return diag.FromErr(err)
	}
	if len(h.mapped) == 0 {
		rd.SetId(noneID)
		return nil
	}
	var req sgroupsAPI.FindFdqnRulesReq
	h.walk(func(k string, r *sgroupsAPI.FdqnRule) bool {
		req.SgFrom = append(req.SgFrom, r.GetSgFrom())
		return true
	})
	resp, err := i.(SGClient).FindFdqnRules(ctx, &req)
	if err != nil {
		return diag.FromErr(err)
	}
	var h1 listedResource[model.FDQNRule]
	h1.init(strings.Join(h.source, h.sep), h.sep)
	for _, rule := range resp.GetRules() {
		var mr model.FDQNRule
		if mr, err = utils.Proto2ModelFDQNRule(rule); err != nil {
			return diag.FromErr(err)
		}
		if id := mr.ID.String(); h.mapped[id] != nil {
			_ = h1.set(id, &mr)
		}
	}
	items = items[:0]
	h1.walk(func(_ string, mr *model.FDQNRule) bool {
		if mr != nil {
			var item any
			if item, err = modelFdqnRule2tf(*mr); err != nil {
				return false
			}
			items = append(items, item)
		}
		return true
	})
	if err != nil {
		return diag.FromErr(err)
	}
	rd.SetId(h1.id(noneID))
	return diag.FromErr(
		rd.Set(RcLabelItems, items),
	)
}

type crudFdqnRules = listedRcCRUD[sgroupsAPI.FdqnRule]

func fdqnRulesU(ctx context.Context, rd *schema.ResourceData, i interface{}) diag.Diagnostics {
	crud := crudFdqnRules{tf2proto: tf2protoFdqnRule, labelItems: RcLabelItems, client: i.(SGClient)}
	return diag.FromErr(crud.update(ctx, rd))
}

func fdqnRulesC(ctx context.Context, rd *schema.ResourceData, i interface{}) diag.Diagnostics {
	crud := crudFdqnRules{tf2proto: tf2protoFdqnRule, labelItems: RcLabelItems, client: i.(SGClient)}
	return diag.FromErr(crud.create(ctx, rd))
}

func fdqnRulesD(ctx context.Context, rd *schema.ResourceData, i interface{}) diag.Diagnostics {
	crud := crudFdqnRules{tf2proto: tf2protoFdqnRule, labelItems: RcLabelItems, client: i.(SGClient)}
	return diag.FromErr(crud.delete(ctx, rd))
}
