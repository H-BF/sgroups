package internal

import (
	"context"
	"fmt"

	utils "github.com/H-BF/sgroups/internal/api/sgroups"
	model "github.com/H-BF/sgroups/internal/models/sgroups"

	sgroupsAPI "github.com/H-BF/protos/pkg/api/sgroups"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

/*// resource skeleton
proto: TCP|UDP
sg_from: sg1
fdqn: aws.com
logs: <true|false>
ports:
- s: 10
  d: 200-210
- s: 100-110
  d: 100
*/

// RcFdqnRule -
const RcFdqnRule = SGroupsProvider + "_fdqn_rule"

// RcLabelFdqn -
const RcLabelFdqn = "fdqn"

// SGroupsRcFdqnRule -
func SGroupsRcFdqnRule() *schema.Resource {
	return &schema.Resource{
		Description:   "FDQN rule",
		ReadContext:   fdqnRuleR,
		CreateContext: fdqnRuleC,
		UpdateContext: func(ctx context.Context, rd *schema.ResourceData, i interface{}) diag.Diagnostics {
			return fdqnRuleUD(ctx, rd, i, true)
		},
		DeleteContext: func(ctx context.Context, rd *schema.ResourceData, i interface{}) diag.Diagnostics {
			return fdqnRuleUD(ctx, rd, i, false)
		},
		Schema: map[string]*schema.Schema{ //nolint:dupl
			RcLabelProto: netProtoSchema(),
			RcLabelSgFrom: {
				Description: "SG from",
				Type:        schema.TypeString,
				Required:    true,
			},
			RcLabelFdqn: {
				Description: "FDQN record",
				Type:        schema.TypeString,
				Required:    true,
			},
			RcLabelLogs: {
				Description: "switch {on|off} logs on every rule in SG",
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
			},
			RcLabelRulePorts: accPortsSchema(),
		},
	}
}

func fdqnRuleR(ctx context.Context, rd *schema.ResourceData, i interface{}) diag.Diagnostics {
	var req sgroupsAPI.FindFdqnRulesReq
	req.SgFrom = append(req.SgFrom, rd.Get(RcLabelSgFrom).(string))
	resp, err := i.(SGClient).FindFdqnRules(ctx, &req)
	if err != nil {
		return diag.FromErr(err)
	}
	var tp model.NetworkTransport
	if err = tp.FromString(rd.Get(RcLabelProto).(string)); err != nil {
		return diag.FromErr(err)
	}
	for _, rule := range resp.GetRules() {
		var mr model.FDQNRule
		if mr, err = utils.Proto2ModelFDQNRule(rule); err != nil {
			return diag.FromErr(err)
		}
		if mr.ID.Transport == tp {
			rc, err := modelFdqnRule2tf(mr)
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
			rd.SetId(mr.ID.String())
			return nil
		}
	}
	rd.SetId("")
	return nil
}

func fdqnRuleC(ctx context.Context, rd *schema.ResourceData, i interface{}) diag.Diagnostics {
	rule, err := rd2protoFdqnRule(rd, true)
	if err != nil {
		return diag.FromErr(err)
	}
	var id model.FDQNRuleIdentity
	if id, err = utils.Proto2ModelFDQNRuleIdentity(rule); err != nil {
		return diag.FromErr(err)
	}
	req := sgroupsAPI.SyncReq{
		SyncOp: sgroupsAPI.SyncReq_Upsert,
		Subject: &sgroupsAPI.SyncReq_FdqnRules{
			FdqnRules: &sgroupsAPI.SyncFdqnRules{
				Rules: []*sgroupsAPI.FdqnRule{rule},
			},
		},
	}
	if _, err = i.(SGClient).Sync(ctx, &req); err == nil {
		rd.SetId(id.String())
	}
	return diag.FromErr(err)
}

func fdqnRuleUD(ctx context.Context, rd *schema.ResourceData, i interface{}, upd bool) diag.Diagnostics {
	rule, err := rd2protoFdqnRule(rd, upd)
	if err != nil {
		return diag.FromErr(err)
	}
	var id model.FDQNRuleIdentity
	if upd {
		for _, a := range []string{RcLabelSgFrom, RcLabelFdqn, RcLabelProto} {
			if rd.HasChange(a) {
				return diag.FromErr(fmt.Errorf("unable change '%s' attribute", a))
			}
		}
		if id, err = utils.Proto2ModelFDQNRuleIdentity(rule); err != nil {
			return diag.FromErr(err)
		}
	}
	op := sgroupsAPI.SyncReq_Upsert
	if !upd {
		op = sgroupsAPI.SyncReq_Delete
	}
	req := sgroupsAPI.SyncReq{
		SyncOp: op,
		Subject: &sgroupsAPI.SyncReq_FdqnRules{
			FdqnRules: &sgroupsAPI.SyncFdqnRules{
				Rules: []*sgroupsAPI.FdqnRule{rule},
			},
		},
	}
	if _, err = i.(SGClient).Sync(ctx, &req); err == nil && upd {
		rd.SetId(id.String())
	}
	return diag.FromErr(err)
}

func modelFdqnRule2tf(mr model.FDQNRule) (map[string]any, error) {
	var ports []any
	for _, p := range mr.Ports {
		var s, d model.PortSource
		err := s.FromPortRanges(p.S)
		if err == nil {
			err = d.FromPortRanges(p.D)
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
		RcLabelSgFrom: mr.ID.SgFrom,
		RcLabelFdqn:   mr.ID.FdqnTo,
		RcLabelProto:  mr.ID.Transport.String(),
		RcLabelLogs:   mr.Logs,
	}
	if len(ports) > 0 {
		ret[RcLabelRulePorts] = ports
	}
	return ret, nil
}

func rd2protoFdqnRule(rd *schema.ResourceData, withPorts bool) (*sgroupsAPI.FdqnRule, error) {
	attrs := []string{
		RcLabelSgFrom, RcLabelFdqn, RcLabelProto, RcLabelLogs,
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
	_, ret, err := tf2protoFdqnRule(raw)
	return ret, err
}

func tf2protoFdqnRule(raw any) (string, *sgroupsAPI.FdqnRule, error) {
	item := raw.(map[string]any)
	proto, e := tf2protoNetProto(item)
	if e != nil {
		return "", nil, e
	}
	rule := &sgroupsAPI.FdqnRule{
		Transport: proto,
		SgFrom:    item[RcLabelSgFrom].(string),
		FDQN:      item[RcLabelFdqn].(string),
	}
	rule.Logs, _ = item[RcLabelLogs].(bool)
	id, err := utils.Proto2ModelFDQNRuleIdentity(rule)
	if err != nil {
		return "", nil, err
	}
	rule.Ports = tf2protoAccPorts(item)
	return id.String(), rule, nil
}
