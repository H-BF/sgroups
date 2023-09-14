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
fqdn: aws.com
logs: <true|false>
ports:
- s: 10
  d: 200-210
- s: 100-110
  d: 100
*/

// RcFqdnRule -
const RcFqdnRule = SGroupsProvider + "_fqdn_rule"

// RcLabelFqdn -
const RcLabelFqdn = "fqdn_to"

// SGroupsRcFqdnRule -
func SGroupsRcFqdnRule() *schema.Resource { //nolint:dupl
	return &schema.Resource{
		Description:   "FQDN rule",
		ReadContext:   fqdnRuleR,
		CreateContext: fqdnRuleC,
		UpdateContext: func(ctx context.Context, rd *schema.ResourceData, i interface{}) diag.Diagnostics {
			return fqdnRuleUD(ctx, rd, i, true)
		},
		DeleteContext: func(ctx context.Context, rd *schema.ResourceData, i interface{}) diag.Diagnostics {
			return fqdnRuleUD(ctx, rd, i, false)
		},
		Schema: map[string]*schema.Schema{ //nolint:dupl
			RcLabelProto: netProtoSchema(),
			RcLabelSgFrom: {
				Description: "SG from",
				Type:        schema.TypeString,
				Required:    true,
			},
			RcLabelFqdn: {
				Description: "FQDN record",
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

func fqdnRuleR(ctx context.Context, rd *schema.ResourceData, i interface{}) diag.Diagnostics {
	var req sgroupsAPI.FindFqdnRulesReq
	req.SgFrom = append(req.SgFrom, rd.Get(RcLabelSgFrom).(string))
	resp, err := i.(SGClient).FindFqdnRules(ctx, &req)
	if err != nil {
		return diag.FromErr(err)
	}
	var tp model.NetworkTransport
	if err = tp.FromString(rd.Get(RcLabelProto).(string)); err != nil {
		return diag.FromErr(err)
	}
	for _, rule := range resp.GetRules() {
		var mr model.FQDNRule
		if mr, err = utils.Proto2ModelFQDNRule(rule); err != nil {
			return diag.FromErr(err)
		}
		if mr.ID.Transport == tp {
			rc, err := modelFqdnRule2tf(mr)
			if err != nil {
				return diag.FromErr(err)
			}
			attrs := []string{
				RcLabelSgFrom, RcLabelFqdn, RcLabelProto, RcLabelRulePorts,
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

func fqdnRuleC(ctx context.Context, rd *schema.ResourceData, i interface{}) diag.Diagnostics { //nolint:dupl
	rule, err := rd2protoFqdnRule(rd, true)
	if err != nil {
		return diag.FromErr(err)
	}
	var id model.FQDNRuleIdentity
	if id, err = utils.Proto2ModelFQDNRuleIdentity(rule); err != nil {
		return diag.FromErr(err)
	}
	req := sgroupsAPI.SyncReq{
		SyncOp: sgroupsAPI.SyncReq_Upsert,
		Subject: &sgroupsAPI.SyncReq_FqdnRules{
			FqdnRules: &sgroupsAPI.SyncFqdnRules{
				Rules: []*sgroupsAPI.FqdnRule{rule},
			},
		},
	}
	if _, err = i.(SGClient).Sync(ctx, &req); err == nil {
		rd.SetId(id.String())
	}
	return diag.FromErr(err)
}

func fqdnRuleUD(ctx context.Context, rd *schema.ResourceData, i interface{}, upd bool) diag.Diagnostics {
	rule, err := rd2protoFqdnRule(rd, upd)
	if err != nil {
		return diag.FromErr(err)
	}
	var id model.FQDNRuleIdentity
	if upd {
		for _, a := range []string{RcLabelSgFrom, RcLabelFqdn, RcLabelProto} {
			if rd.HasChange(a) {
				return diag.FromErr(fmt.Errorf("unable change '%s' attribute", a))
			}
		}
		if id, err = utils.Proto2ModelFQDNRuleIdentity(rule); err != nil {
			return diag.FromErr(err)
		}
	}
	op := sgroupsAPI.SyncReq_Upsert
	if !upd {
		op = sgroupsAPI.SyncReq_Delete
	}
	req := sgroupsAPI.SyncReq{
		SyncOp: op,
		Subject: &sgroupsAPI.SyncReq_FqdnRules{
			FqdnRules: &sgroupsAPI.SyncFqdnRules{
				Rules: []*sgroupsAPI.FqdnRule{rule},
			},
		},
	}
	if _, err = i.(SGClient).Sync(ctx, &req); err == nil && upd {
		rd.SetId(id.String())
	}
	return diag.FromErr(err)
}

func modelFqdnRule2tf(mr model.FQDNRule) (map[string]any, error) { //nolint:dupl
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
		RcLabelFqdn:   mr.ID.FqdnTo,
		RcLabelProto:  mr.ID.Transport.String(),
		RcLabelLogs:   mr.Logs,
	}
	if len(ports) > 0 {
		ret[RcLabelRulePorts] = ports
	}
	return ret, nil
}

func rd2protoFqdnRule(rd *schema.ResourceData, withPorts bool) (*sgroupsAPI.FqdnRule, error) {
	attrs := []string{
		RcLabelSgFrom, RcLabelFqdn, RcLabelProto, RcLabelLogs,
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
	_, ret, err := tf2protoFqdnRule(raw)
	return ret, err
}

func tf2protoFqdnRule(raw any) (string, *sgroupsAPI.FqdnRule, error) { //nolint:dupl
	item := raw.(map[string]any)
	proto, e := tf2protoNetProto(item)
	if e != nil {
		return "", nil, e
	}
	rule := &sgroupsAPI.FqdnRule{
		Transport: proto,
		SgFrom:    item[RcLabelSgFrom].(string),
		FQDN:      item[RcLabelFqdn].(string),
	}
	rule.Logs, _ = item[RcLabelLogs].(bool)
	id, err := utils.Proto2ModelFQDNRuleIdentity(rule)
	if err != nil {
		return "", nil, err
	}
	rule.Ports = tf2protoAccPorts(item)
	return id.String(), rule, nil
}
