package internal

import (
	"context"
	"fmt"
	"strings"

	utils "github.com/H-BF/sgroups/internal/api/sgroups"
	model "github.com/H-BF/sgroups/internal/models/sgroups"

	"github.com/H-BF/protos/pkg/api/common"
	sgroupsAPI "github.com/H-BF/protos/pkg/api/sgroups"
	"github.com/hashicorp/go-cty/cty"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/pkg/errors"
)

const (
	// RcRules -
	RcRules = SGroupsProvider + "_rules"
	// RcLabelSgFrom -
	RcLabelSgFrom = "sg_from"
	// RcLabelSgTo -
	RcLabelSgTo = "sg_to"
	// RcLabelProto -
	RcLabelProto = "proto"
	// RcLabelSPorts -
	RcLabelSPorts = "s"
	// RcLabelDPorts -
	RcLabelDPorts = "d"
	//RcLabelRulePorts -
	RcLabelRulePorts = "ports"
)

/*// respurce skeleton
items:
- proto: TCP
  sg_from: sg1
  sg_to: sg2
  ports:
  - s: 10
    d: 200-210
  - s: 100-110
    d: 100
- proto: UDP
  sg_from: sg1
  sg_to: sg2
  ports:
  - s: 10
    d: 200-210
  - s: 100-110
    d: 100
*/

// SGroupsRcRules sg-rules resource
func SGroupsRcRules() *schema.Resource {
	return &schema.Resource{
		Description:   fmt.Sprintf("represents SG rules resource in '%s' provider", SGroupsProvider),
		CreateContext: rulesC,
		UpdateContext: rulesU,
		DeleteContext: rulesD,
		ReadContext:   rulesR,
		Schema: map[string]*schema.Schema{
			RcLabelItems: {
				Optional:    true,
				Description: "SG rules list",
				Type:        schema.TypeList,
				Elem: &schema.Resource{
					Description: "SG rule element",
					Schema: map[string]*schema.Schema{
						RcLabelProto: {
							Description: "ip-proto tcp|udp",
							Type:        schema.TypeString,
							Required:    true,
							ValidateDiagFunc: func(i interface{}, p cty.Path) diag.Diagnostics {
								s := i.(string)
								ok := strings.EqualFold(common.Networks_NetIP_TCP.String(), s) ||
									strings.EqualFold(common.Networks_NetIP_UDP.String(), s)
								if ok {
									return nil
								}
								return diag.Errorf("bad proto: '%s'", s)
							},
						},
						RcLabelSgFrom: {
							Description: "SG from",
							Type:        schema.TypeString,
							Required:    true,
						},
						RcLabelSgTo: {
							Description: "SG to",
							Type:        schema.TypeString,
							Required:    true,
						},
						RcLabelRulePorts: {
							Description:      "access ports",
							Type:             schema.TypeList,
							Optional:         true,
							DiffSuppressFunc: diffSuppressSGRulePorts,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									RcLabelSPorts: {
										Description:      "source port or ports range",
										Type:             schema.TypeString,
										ValidateDiagFunc: validatePortOrRange,
										Optional:         true,
									},
									RcLabelDPorts: {
										Description:      "dest port or poprts range",
										Type:             schema.TypeString,
										ValidateDiagFunc: validatePortOrRange,
										Optional:         true,
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

type crudRules = listedRcCRUD[sgroupsAPI.Rule]

func rulesR(ctx context.Context, rd *schema.ResourceData, i interface{}) diag.Diagnostics {
	items, _ := rd.Get(RcLabelItems).([]any)
	var h listedResource[sgroupsAPI.Rule]
	h.init("", ";")
	if err := h.addlist(items, tf2protoRule); err != nil {
		return diag.FromErr(err)
	}
	if len(h.mapped) == 0 {
		rd.SetId(noneID)
		return nil
	}
	var req sgroupsAPI.FindRulesReq
	h.walk(func(k string, r *sgroupsAPI.Rule) bool {
		req.SgFrom = append(req.SgFrom, r.GetSgFrom())
		req.SgTo = append(req.SgTo, r.GetSgTo())
		return true
	})
	resp, err := i.(SGClient).FindRules(ctx, &req)
	if err != nil {
		return diag.FromErr(err)
	}
	var h1 listedResource[model.SGRule]
	h1.init(strings.Join(h.source, h.sep), h.sep)
	for _, rule := range resp.GetRules() {
		var mr model.SGRule
		if mr, err = utils.Proto2ModelSGRule(rule); err != nil {
			return diag.FromErr(err)
		}
		if id := mr.String(); h.mapped[id] != nil {
			_ = h1.set(id, &mr)
		}
	}
	items = items[:0]
	h1.walk(func(_ string, mr *model.SGRule) bool {
		if mr != nil {
			var item any
			if item, err = modelRule2tf(mr); err != nil {
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

func rulesU(ctx context.Context, rd *schema.ResourceData, i interface{}) diag.Diagnostics {
	crud := crudRules{tf2proto: tf2protoRule, labelItems: RcLabelItems, client: i.(SGClient)}
	return diag.FromErr(crud.update(ctx, rd))
}

func rulesC(ctx context.Context, rd *schema.ResourceData, i interface{}) diag.Diagnostics {
	crud := crudRules{tf2proto: tf2protoRule, labelItems: RcLabelItems, client: i.(SGClient)}
	return diag.FromErr(crud.create(ctx, rd))
}

func rulesD(ctx context.Context, rd *schema.ResourceData, i interface{}) diag.Diagnostics {
	crud := crudRules{tf2proto: tf2protoRule, labelItems: RcLabelItems, client: i.(SGClient)}
	return diag.FromErr(crud.delete(ctx, rd))
}

func validatePortOrRange(i interface{}, _ cty.Path) diag.Diagnostics {
	src := i.(string)
	if model.PortSource(src).IsValid() {
		return nil
	}
	return diag.FromErr(errors.Errorf("bad port or range: '%s'", src))
}

func modelRule2tf(mr *model.SGRule) (map[string]any, error) {
	var ports []any
	for _, p := range mr.Ports {
		var s, d model.PortSource
		err := s.FromPortRange(p.S)
		if err == nil {
			err = d.FromPortRange(p.D)
		}
		if err != nil {
			return nil, err
		}
		itm := make(map[string]any)
		if len(s) > 0 {
			itm[RcLabelSPorts] = string(s)
		}
		if len(d) > 0 {
			itm[RcLabelDPorts] = string(d)
		}
		if len(itm) > 0 {
			ports = append(ports, itm)
		}
	}
	ret := map[string]any{
		RcLabelSgFrom: mr.SgFrom.Name,
		RcLabelSgTo:   mr.SgTo.Name,
		RcLabelProto:  mr.Transport.String(),
	}
	if len(ports) > 0 {
		ret[RcLabelRulePorts] = ports
	}
	return ret, nil
}

func tf2protoRule(raw any) (string, *sgroupsAPI.Rule, error) {
	item := raw.(map[string]any)
	proto, ok := common.Networks_NetIP_Transport_value[strings.ToUpper(item[RcLabelProto].(string))]
	if !ok {
		return "", nil, errors.Errorf("bad proto '%s'", item[RcLabelProto].(string))
	}
	rule := &sgroupsAPI.Rule{
		Transport: common.Networks_NetIP_Transport(proto),
		SgFrom:    item[RcLabelSgFrom].(string),
		SgTo:      item[RcLabelSgTo].(string),
	}
	id, err := utils.Proto2ModelSGRuleIdentity(rule)
	if err != nil {
		return "", nil, err
	}
	ports, _ := item[RcLabelRulePorts].([]any)
	for _, p := range ports {
		if rp, _ := p.(map[string]any); rp != nil {
			s, _ := rp[RcLabelSPorts].(string)
			d, _ := rp[RcLabelDPorts].(string)
			if len(s) > 0 || len(d) > 0 {
				rule.Ports = append(rule.Ports, &sgroupsAPI.Rule_Ports{
					S: s,
					D: d,
				})
			}
		}
	}
	return id.String(), rule, nil
}

func diffSuppressSGRulePorts(k, _, _ string, rd *schema.ResourceData) bool {
	f := func(raw []any) ([]model.SGRulePorts, bool) {
		if len(raw) == 0 {
			return nil, true
		}
		var ret []model.SGRulePorts
		for _, r := range raw {
			if p, _ := r.(map[string]any); p != nil {
				s, _ := p[RcLabelSPorts].(string)
				d, _ := p[RcLabelDPorts].(string)
				r1, _ := model.PortSource(s).ToPortRange()
				r2, _ := model.PortSource(d).ToPortRange()
				x := model.SGRulePorts{
					S: r1, D: r2,
				}
				if x.Validate() != nil {
					return nil, false
				}
				ret = append(ret, x)
			}
		}
		return ret, true
	}
	if i := strings.Index(k, RcLabelRulePorts); i >= 0 {
		k1 := k[:i] + RcLabelRulePorts
		if rd.HasChange(k1) {
			v1, v2 := rd.GetChange(k1)
			p1, ok1 := f(v1.([]any))
			p2, ok2 := f(v2.([]any))
			if !(ok1 && ok2) {
				return false
			}
			return model.AreRulePortsEq(p1, p2)
		}
	}
	return false
}
