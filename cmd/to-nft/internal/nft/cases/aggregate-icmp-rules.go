package cases

import (
	"context"

	conv "github.com/H-BF/sgroups/internal/api/sgroups"
	model "github.com/H-BF/sgroups/internal/domains/sgroups"

	"github.com/H-BF/corlib/pkg/dict"
	sgAPI "github.com/H-BF/protos/pkg/api/sgroups"
	"github.com/pkg/errors"
)

type (
	// SgSgIcmpRules -
	SgSgIcmpRules struct {
		Rules dict.HDict[model.SgSgIcmpRuleID, *model.SgSgIcmpRule]
	}

	// SgIcmpRules -
	SgIcmpRules struct {
		Rules dict.HDict[model.SgIcmpRuleID, *model.SgIcmpRule]
	}

	// SgIeSgIcmpRules -
	SgIeSgIcmpRules struct {
		Rules dict.HDict[model.IESgSgIcmpRuleID, *model.IESgSgIcmpRule]
	}
)

// IsEq -
func (rules *SgIcmpRules) IsEq(other SgIcmpRules) bool {
	return rules.Rules.Eq(&other.Rules, func(vL, vR *model.SgIcmpRule) bool {
		return vL.IsEq(*vR)
	})
}

// IsEq -
func (rules *SgSgIcmpRules) IsEq(other SgSgIcmpRules) bool {
	return rules.Rules.Eq(&other.Rules, func(vL, vR *model.SgSgIcmpRule) bool {
		return vL.IsEq(*vR)
	})
}

func (rules *SgIeSgIcmpRules) IsEq(other SgIeSgIcmpRules) bool {
	return rules.Rules.Eq(&other.Rules, func(vL, vR *model.IESgSgIcmpRule) bool {
		return vL.IsEq(*vR)
	})
}

// Load get sg-sg-icmp rules from local SG(s)
func (rules *SgSgIcmpRules) Load(ctx context.Context, client SGClient, locals SGs) (err error) {
	const api = "SgSgIcmpRules/Load"

	defer func() {
		err = errors.WithMessage(err, api)
	}()

	localSgNames := locals.Names()
	if len(localSgNames) == 0 {
		return nil
	}
	reqs := []sgAPI.FindSgSgIcmpRulesReq{
		{SgFrom: localSgNames}, {SgTo: localSgNames},
	}
	for i := range reqs {
		var resp *sgAPI.SgSgIcmpRulesResp
		if resp, err = client.FindSgSgIcmpRules(ctx, &reqs[i]); err != nil {
			return err
		}
		for _, protoRule := range resp.GetRules() {
			var rule model.SgSgIcmpRule
			if rule, err = conv.Proto2MOdelSgSgIcmpRule(protoRule); err != nil {
				return err
			}
			_ = rules.Rules.Insert(rule.ID(), &rule)
		}
	}
	return nil
}

// Load get sg-icmp rules from local SG(s)
func (rules *SgIcmpRules) Load(ctx context.Context, client SGClient, locals SGs) (err error) {
	const api = "SgIcmpRules/Load"

	defer func() {
		err = errors.WithMessage(err, api)
	}()

	var req sgAPI.FindSgIcmpRulesReq
	var resp *sgAPI.SgIcmpRulesResp
	if req.SG = locals.Names(); len(req.SG) == 0 {
		return nil
	}
	if resp, err = client.FindSgIcmpRules(ctx, &req); err != nil {
		return err
	}
	for _, protoRule := range resp.GetRules() {
		var rule model.SgIcmpRule
		if rule, err = conv.Proto2MOdelSgIcmpRule(protoRule); err != nil {
			return err
		}
		_ = rules.Rules.Insert(rule.ID(), &rule)
	}
	return nil
}

// Load get sg-sg-ie-icmp rules from local SG(s)
func (rules *SgIeSgIcmpRules) Load(ctx context.Context, client SGClient, locals SGs) (err error) {
	const api = "SgIeSgIcmpRules/Load"

	defer func() {
		err = errors.WithMessage(err, api)
	}()

	var req sgAPI.FindIESgSgIcmpRulesReq
	var resp *sgAPI.IESgSgIcmpRulesResp
	if req.SgLocal = locals.Names(); len(req.SgLocal) == 0 {
		return nil
	}
	if resp, err = client.FindIESgSgIcmpRules(ctx, &req); err != nil {
		return err
	}
	for _, protoRule := range resp.GetRules() {
		var rule model.IESgSgIcmpRule
		if rule, err = conv.Proto2ModelIESgSgIcmpRule(protoRule); err != nil {
			return err
		}
		rules.Rules.Insert(rule.ID(), &rule)
	}
	return nil
}

// In -
func (rules SgSgIcmpRules) In(sgTo string) (ret []model.SgSgIcmpRule) { //nolint:dupl
	rules.Rules.Iterate(func(k model.SgSgIcmpRuleID, v *model.SgSgIcmpRule) bool {
		if k.SgTo == sgTo {
			ret = append(ret, *v)
		}
		return true
	})
	return ret
}

// Out -
func (rules SgSgIcmpRules) Out(sgFrom string) (ret []model.SgSgIcmpRule) { //nolint:dupl
	rules.Rules.Iterate(func(k model.SgSgIcmpRuleID, v *model.SgSgIcmpRule) bool {
		if k.SgFrom == sgFrom {
			ret = append(ret, *v)
		}
		return true
	})
	return ret
}

// Rules4Sg -
func (rules SgIcmpRules) Rules4Sg(sgName string) (ret []model.SgIcmpRule) {
	rules.Rules.Iterate(func(k model.SgIcmpRuleID, v *model.SgIcmpRule) bool {
		if k.Sg == sgName {
			ret = append(ret, *v)
		}
		return true
	})
	return ret
}

// GetRulesForTrafficAndSG -
func (rules *SgIeSgIcmpRules) GetRulesForTrafficAndSG(tr model.Traffic, sg string) (ret []*model.IESgSgIcmpRule) {
	rules.Rules.Iterate(func(k model.IESgSgIcmpRuleID, v *model.IESgSgIcmpRule) bool {
		if k.Traffic == tr && k.SgLocal == sg {
			ret = append(ret, v)
		}
		return true
	})
	return ret
}
