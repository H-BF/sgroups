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
  fqdn: aws.com
  logs: <true|false>
  ports:
  - s: 10
    d: 200-210
  - s: 100-110
    d: 100
*/

// RcFqdnRules -
const RcFqdnRules = SGroupsProvider + "_fqdn_rules"

// SGroupsRcFqdnRules -
func SGroupsRcFqdnRules() *schema.Resource {
	itemRC := SGroupsRcFqdnRule()
	itemRC.CreateContext = nil
	itemRC.ReadContext = nil
	itemRC.UpdateContext = nil
	itemRC.DeleteContext = nil
	return &schema.Resource{
		Description:   fmt.Sprintf("represents FQDN rules resource in '%s' provider", SGroupsProvider),
		CreateContext: fqdnRulesC,
		ReadContext:   fqdnRulesR,
		UpdateContext: fqdnRulesU,
		DeleteContext: fqdnRulesD,
		Schema: map[string]*schema.Schema{
			RcLabelItems: {
				Optional:    true,
				Description: "FQDN rules list",
				Type:        schema.TypeList,
				Elem:        itemRC,
			},
		},
	}
}

func fqdnRulesR(ctx context.Context, rd *schema.ResourceData, i interface{}) diag.Diagnostics {
	items, _ := rd.Get(RcLabelItems).([]any)
	var h listedResource[sgroupsAPI.FqdnRule]
	h.init("", ";")
	if err := h.addlist(items, tf2protoFqdnRule); err != nil {
		return diag.FromErr(err)
	}
	if len(h.mapped) == 0 {
		rd.SetId(noneID)
		return nil
	}
	var req sgroupsAPI.FindFqdnRulesReq
	h.walk(func(k string, r *sgroupsAPI.FqdnRule) bool {
		req.SgFrom = append(req.SgFrom, r.GetSgFrom())
		return true
	})
	resp, err := i.(SGClient).FindFqdnRules(ctx, &req)
	if err != nil {
		return diag.FromErr(err)
	}
	var h1 listedResource[model.FQDNRule]
	h1.init(strings.Join(h.source, h.sep), h.sep)
	for _, rule := range resp.GetRules() {
		var mr model.FQDNRule
		if mr, err = utils.Proto2ModelFQDNRule(rule); err != nil {
			return diag.FromErr(err)
		}
		if id := mr.ID.String(); h.mapped[id] != nil {
			_ = h1.set(id, &mr)
		}
	}
	items = items[:0]
	h1.walk(func(_ string, mr *model.FQDNRule) bool {
		if mr != nil {
			var item any
			if item, err = modelFqdnRule2tf(*mr); err != nil {
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

type crudFqdnRules = listedRcCRUD[sgroupsAPI.FqdnRule]

func fqdnRulesU(ctx context.Context, rd *schema.ResourceData, i interface{}) diag.Diagnostics {
	crud := crudFqdnRules{tf2proto: tf2protoFqdnRule, labelItems: RcLabelItems, client: i.(SGClient)}
	return diag.FromErr(crud.update(ctx, rd))
}

func fqdnRulesC(ctx context.Context, rd *schema.ResourceData, i interface{}) diag.Diagnostics {
	crud := crudFqdnRules{tf2proto: tf2protoFqdnRule, labelItems: RcLabelItems, client: i.(SGClient)}
	return diag.FromErr(crud.create(ctx, rd))
}

func fqdnRulesD(ctx context.Context, rd *schema.ResourceData, i interface{}) diag.Diagnostics {
	crud := crudFqdnRules{tf2proto: tf2protoFqdnRule, labelItems: RcLabelItems, client: i.(SGClient)}
	return diag.FromErr(crud.delete(ctx, rd))
}
