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

/*// respurce skeleton
proto: TCP
sg_from: sg1
sg_to: sg2
ports_from: 200-300 500-600 22 24
ports_to: 200-300 500-600 22 24
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
					return diag.FromErr(fmt.Errorf("bad proto: '%s'", s))
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
			RcLabelPortsFrom: {
				Description:      "port ranges from",
				Type:             schema.TypeString,
				ValidateDiagFunc: validatePortRanges,
				Optional:         true,
				DiffSuppressFunc: portRangesNoDiff,
			},
			RcLabelPortsTo: {
				Description:      "port ranges to",
				Type:             schema.TypeString,
				ValidateDiagFunc: validatePortRanges,
				Optional:         true,
				DiffSuppressFunc: portRangesNoDiff,
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
			attrs := []struct {
				name string
				val  any
			}{
				{RcLabelSgFrom, mr.SgFrom.Name},
				{RcLabelSgTo, mr.SgTo.Name},
				{RcLabelProto, mr.Transport.String()},
				{RcLabelPortsFrom, foldPorts(mr.PortsFrom)},
				{RcLabelPortsTo, foldPorts(mr.PortsTo)},
			}
			for _, a := range attrs {
				if err = rd.Set(a.name, a.val); err != nil {
					return diag.FromErr(err)
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
	proto := common.Networks_NetIP_Transport_value[strings.ToUpper(rd.Get(RcLabelProto).(string))]
	rule := sgroupsAPI.Rule{
		Transport: common.Networks_NetIP_Transport(proto),
		SgFrom: &sgroupsAPI.SecGroup{
			Name: rd.Get(RcLabelSgFrom).(string),
		},
		SgTo: &sgroupsAPI.SecGroup{
			Name: rd.Get(RcLabelSgTo).(string),
		},
	}
	if withPorts {
		var err error
		if rule.PortsFrom, err = rd2protoPortsRanges(RcLabelPortsFrom, rd); err != nil {
			return nil, errors.WithMessage(err, "ports-from")
		}
		if rule.PortsTo, err = rd2protoPortsRanges(RcLabelPortsTo, rd); err != nil {
			return nil, errors.WithMessage(err, "ports-to")
		}
	}
	return &rule, nil
}

func str2protoPortsRanges(portsSrc string) ([]*common.Networks_NetIP_PortRange, error) {
	var ret []*common.Networks_NetIP_PortRange
	err := parsePorts(portsSrc, func(start, end uint16) error {
		ret = append(ret, &common.Networks_NetIP_PortRange{
			From: uint32(start),
			To:   uint32(end),
		})
		return nil
	})
	return ret, errors.WithMessagef(err, "bad port range '%s'", portsSrc)
}

func rd2protoPortsRanges(k string, rd *schema.ResourceData) ([]*common.Networks_NetIP_PortRange, error) {
	var ret []*common.Networks_NetIP_PortRange
	var err error
	if raw, ok := rd.GetOk(k); ok {
		ret, err = str2protoPortsRanges(raw.(string))
	}
	return ret, err
}

func portRangesNoDiff(_, oldValue, newValue string, _ *schema.ResourceData) bool {
	l, e1 := str2protoPortsRanges(oldValue)
	r, e2 := str2protoPortsRanges(newValue)
	if e1 != nil || e2 != nil {
		return false
	}
	rrL := utils.Proto2ModelPortRanges(l)
	rrR := utils.Proto2ModelPortRanges(r)
	return model.ArePortRangesEq(rrL, rrR)
}
