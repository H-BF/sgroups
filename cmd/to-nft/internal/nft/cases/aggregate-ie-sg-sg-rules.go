package cases

import (
	"context"

	conv "github.com/H-BF/sgroups/internal/api/sgroups"
	model "github.com/H-BF/sgroups/internal/models/sgroups"

	"github.com/H-BF/corlib/pkg/dict"
	sgAPI "github.com/H-BF/protos/pkg/api/sgroups"
	"github.com/pkg/errors"
)

// SgIeSgRules -
type SgIeSgRules struct {
	Rules dict.HDict[model.IESgSgRuleIdentity, *model.IESgSgRule]
}

// IsEq -
func (rules *SgIeSgRules) IsEq(other SgIeSgRules) bool {
	return rules.Rules.Eq(&other.Rules, func(vL, vR *model.IESgSgRule) bool {
		return vL.IsEq(*vR)
	})
}

// GetRulesForTrafficAndSG -
func (rules *SgIeSgRules) GetRulesForTrafficAndSG(tr model.Traffic, sg string) (ret []*model.IESgSgRule) {
	rules.Rules.Iterate(func(k model.IESgSgRuleIdentity, v *model.IESgSgRule) bool {
		if k.Traffic == tr && k.SgLocal == sg {
			ret = append(ret, v)
		}
		return true
	})
	return ret
}

// Load -
func (rules *SgIeSgRules) Load(ctx context.Context, client SGClient, locals SGs) (err error) {
	const api = "sg-ie-sg-rules/Load"

	defer func() {
		err = errors.WithMessage(err, api)
	}()

	localSgNames := locals.Names()
	if len(localSgNames) == 0 {
		return nil
	}
	req := sgAPI.FindIESgSgRulesReq{SgLocal: localSgNames}
	var resp *sgAPI.IESgSgRulesResp
	if resp, err = client.FindIESgSgRules(ctx, &req); err != nil {
		return err
	}
	for _, protoRule := range resp.GetRules() {
		var rule model.IESgSgRule
		if rule, err = conv.Proto2ModelSgSgRule(protoRule); err != nil {
			return err
		}
		_ = rules.Rules.Insert(rule.ID, &rule)
	}
	return nil
}
