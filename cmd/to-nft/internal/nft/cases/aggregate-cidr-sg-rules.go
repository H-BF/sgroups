package cases

import (
	"context"

	sgAPI "github.com/H-BF/protos/pkg/api/sgroups"
	conv "github.com/H-BF/sgroups/internal/api/sgroups"
	"github.com/H-BF/sgroups/internal/dict"
	model "github.com/H-BF/sgroups/internal/models/sgroups"

	"github.com/pkg/errors"
)

// CidrSgRules -
type CidrSgRules struct {
	SGs   SGs
	Rules dict.RBDict[model.CidrSgRuleIdenity, *model.CidrSgRule]
}

// IsEq -
func (rules *CidrSgRules) IsEq(order CidrSgRules) bool {
	eq := rules.SGs.IsEq(order.SGs)
	if eq {
		eq = rules.Rules.Eq(&order.Rules, func(vL, vR *model.CidrSgRule) bool {
			return vL.IsEq(*vR)
		})
	}
	return eq
}

func (rules *CidrSgRules) Load(ctx context.Context, client SGClient, locals SGs) (err error) {
	const api = "cidr-sg-rules/Load"

	defer func() {
		err = errors.WithMessage(err, api)
	}()

	rules.Rules.Clear()
	rules.SGs.Clear()
	req := sgAPI.FindCidrSgRulesReq{Sg: locals.Names()}
	if len(req.Sg) == 0 {
		return nil
	}
	var resp *sgAPI.CidrSgRulesResp
	if resp, err = client.FindCidrSgRules(ctx, &req); err != nil {
		return err
	}
	for _, protoRule := range resp.GetRules() {
		var rule model.CidrSgRule
		_ = conv.Proto2ModelSGRule
		if rule, err = conv.Proto2ModelCidrSgRule(protoRule); err != nil {
			return err
		}
		switch rule.ID.Traffic {
		case model.EGRESS, model.INGRESS:
			if sg := locals.At(rule.ID.SG); sg != nil {
				rules.SGs.Insert(sg.Name, sg)
				_ = rules.Rules.Insert(rule.ID, &rule)
			}
		}
	}
	return nil
}

// GetRulesForTrafficAndSG -
func (rules *CidrSgRules) GetRulesForTrafficAndSG(tr model.Traffic, sg string) []*model.CidrSgRule {
	var ret []*model.CidrSgRule
	rules.Rules.Iterate(func(_ model.CidrSgRuleIdenity, r *model.CidrSgRule) bool {
		if r.ID.SG == sg && r.ID.Traffic == tr {
			ret = append(ret, r)
		}
		return true
	})
	return ret
}
