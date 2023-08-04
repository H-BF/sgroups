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
)

/*// respurce skeleton
proto: TCP
sg_from: sg1
sg_to: sg2
logs: <true|false>
ports:
- s: 10
  d: 200-210
- s: 100-110
  d: 100
*/

// RcRule -
const RcRule = SGroupsProvider + "_rule"

// SGroupsRcRule -
func SGroupsRcRule() *schema.Resource {
	return &schema.Resource{
		Description:   "SG rule element",
		ReadContext:   ruleR,
		CreateContext: ruleC,
		UpdateContext: func(ctx context.Context, rd *schema.ResourceData, i interface{}) diag.Diagnostics {
			return ruleUD(ctx, rd, i, true)
		},
		DeleteContext: func(ctx context.Context, rd *schema.ResourceData, i interface{}) diag.Diagnostics {
			return ruleUD(ctx, rd, i, false)
		},
		Schema: map[string]*schema.Schema{ //nolint:dupl
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
			RcLabelLogs: {
				Description: "switch {on|off} logs on every rule in SG",
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
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
	}
}

func ruleR(ctx context.Context, rd *schema.ResourceData, i interface{}) diag.Diagnostics {
	var req sgroupsAPI.FindRulesReq
	req.SgFrom = append(req.SgFrom, rd.Get(RcLabelSgFrom).(string))
	req.SgTo = append(req.SgTo, rd.Get(RcLabelSgTo).(string))
	resp, err := i.(SGClient).FindRules(ctx, &req)
	if err != nil {
		return diag.FromErr(err)
	}
	var tp model.NetworkTransport
	if err = tp.FromString(rd.Get(RcLabelProto).(string)); err != nil {
		return diag.FromErr(err)
	}
	for _, rule := range resp.GetRules() {
		var mr model.SGRule
		if mr, err = utils.Proto2ModelSGRule(rule); err != nil {
			return diag.FromErr(err)
		}
		if mr.Transport == tp {
			rc, err := modelRule2tf(&mr)
			if err != nil {
				return diag.FromErr(err)
			}
			attrs := []string{
				RcLabelSgFrom, RcLabelSgTo, RcLabelProto, RcLabelRulePorts,
			}
			for _, a := range attrs {
				if v, ok := rc[a]; ok {
					if err = rd.Set(a, v); err != nil {
						return diag.FromErr(err)
					}
				}
			}
			rd.SetId(mr.SGRuleIdentity.String())
			return nil
		}
	}
	rd.SetId("")
	return nil
}

func ruleC(ctx context.Context, rd *schema.ResourceData, i interface{}) diag.Diagnostics {
	rule, err := rd2protoRule(rd, true)
	if err != nil {
		return diag.FromErr(err)
	}
	var id model.SGRuleIdentity
	if id, err = utils.Proto2ModelSGRuleIdentity(rule); err != nil {
		return diag.FromErr(err)
	}
	req := sgroupsAPI.SyncReq{
		SyncOp: sgroupsAPI.SyncReq_Upsert,
		Subject: &sgroupsAPI.SyncReq_SgRules{
			SgRules: &sgroupsAPI.SyncSGRules{
				Rules: []*sgroupsAPI.Rule{rule},
			},
		},
	}
	if _, err = i.(SGClient).Sync(ctx, &req); err == nil {
		rd.SetId(id.String())
	}
	return diag.FromErr(err)
}

func ruleUD(ctx context.Context, rd *schema.ResourceData, i interface{}, upd bool) diag.Diagnostics {
	rule, err := rd2protoRule(rd, upd)
	if err != nil {
		return diag.FromErr(err)
	}
	var id model.SGRuleIdentity
	if upd {
		for _, a := range []string{RcLabelSgFrom, RcLabelSgTo, RcLabelProto} {
			if rd.HasChange(a) {
				return diag.FromErr(fmt.Errorf("unable change '%s' attribute", a))
			}
		}
		if id, err = utils.Proto2ModelSGRuleIdentity(rule); err != nil {
			return diag.FromErr(err)
		}
	}
	op := sgroupsAPI.SyncReq_Upsert
	if !upd {
		op = sgroupsAPI.SyncReq_Delete
	}
	req := sgroupsAPI.SyncReq{
		SyncOp: op,
		Subject: &sgroupsAPI.SyncReq_SgRules{
			SgRules: &sgroupsAPI.SyncSGRules{
				Rules: []*sgroupsAPI.Rule{rule},
			},
		},
	}
	if _, err = i.(SGClient).Sync(ctx, &req); err == nil && upd {
		rd.SetId(id.String())
	}
	return diag.FromErr(err)
}

func rd2protoRule(rd *schema.ResourceData, withPorts bool) (*sgroupsAPI.Rule, error) {
	attrs := []string{
		RcLabelSgFrom, RcLabelSgTo, RcLabelProto, RcLabelLogs,
	}
	if withPorts {
		attrs = append(attrs, RcLabelRulePorts)
	}
	raw := make(map[string]any)
	for _, a := range attrs {
		if v, ok := rd.GetOk(a); ok {
			raw[a] = v
		}
	}
	_, ret, err := tf2protoRule(raw)
	return ret, err
}
