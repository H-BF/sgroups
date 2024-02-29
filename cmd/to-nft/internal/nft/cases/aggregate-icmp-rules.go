package cases

import (
	"context"

	conv "github.com/H-BF/sgroups/internal/api/sgroups"
	"github.com/H-BF/sgroups/internal/dict"
	model "github.com/H-BF/sgroups/internal/models/sgroups"

	sgAPI "github.com/H-BF/protos/pkg/api/sgroups"
	"github.com/pkg/errors"
)

type (
	// SgSgIcmpRules -
	SgSgIcmpRules struct {
		SGs   SGs
		Rules dict.HDict[model.SgSgIcmpRuleID, *model.SgSgIcmpRule]
	}

	// SgIcmpRules -
	SgIcmpRules struct {
		SGs   SGs
		Rules dict.HDict[model.SgIcmpRuleID, *model.SgIcmpRule]
	}

	// SgIeSgIcmpRules -
	SgIeSgIcmpRules struct {
		SGs   SGs
		Rules dict.HDict[model.IESgSgIcmpRuleID, *model.IESgSgIcmpRule]
	}
)

// IsEq -
func (rules *SgIcmpRules) IsEq(other SgIcmpRules) bool {
	eq := rules.SGs.IsEq(other.SGs)
	if eq {
		eq = rules.Rules.Eq(&other.Rules, func(vL, vR *model.SgIcmpRule) bool {
			return vL.IsEq(*vR)
		})
	}
	return eq
}

// IsEq -
func (rules *SgSgIcmpRules) IsEq(other SgSgIcmpRules) bool {
	eq := rules.SGs.IsEq(other.SGs)
	if eq {
		eq = rules.Rules.Eq(&other.Rules, func(vL, vR *model.SgSgIcmpRule) bool {
			return vL.IsEq(*vR)
		})
	}
	return eq
}

func (rules *SgIeSgIcmpRules) IsEq(other SgIeSgIcmpRules) bool {
	eq := rules.SGs.IsEq(other.SGs)
	if eq {
		eq = rules.Rules.Eq(&other.Rules, func(vL, vR *model.IESgSgIcmpRule) bool {
			return vL.IsEq(*vR)
		})
	}
	return eq
}

// Load get sg-sg-icmp rules from local SG(s)
func (rules *SgSgIcmpRules) Load(ctx context.Context, client SGClient, locals SGs) (err error) {
	const api = "SgSgIcmpRules/Load"

	defer func() {
		err = errors.WithMessage(err, api)
	}()

	rules.SGs.Clear()
	rules.Rules.Clear()
	localSgNames := locals.Names()
	if len(localSgNames) == 0 {
		return nil
	}
	reqs := []sgAPI.FindSgSgIcmpRulesReq{
		{SgFrom: localSgNames}, {SgTo: localSgNames},
	}
	var nonLocalSgs []string
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
			rules.Rules.Insert(rule.ID(), &rule)
			for _, sgN := range []string{rule.SgFrom, rule.SgTo} {
				if sg := locals.At(sgN); sg != nil {
					_ = rules.SGs.Insert(sgN, sg)
				} else {
					nonLocalSgs = append(nonLocalSgs, sgN)
				}
			}
		}
	}
	return rules.SGs.LoadFromNames(ctx, client, nonLocalSgs)
}

// Load get sg-icmp rules from local SG(s)
func (rules *SgIcmpRules) Load(ctx context.Context, client SGClient, locals SGs) (err error) {
	const api = "SgIcmpRules/Load"

	defer func() {
		err = errors.WithMessage(err, api)
	}()

	rules.SGs.Clear()
	rules.Rules.Clear()
	var req sgAPI.FindSgIcmpRulesReq
	var resp *sgAPI.SgIcmpRulesResp
	if req.Sg = locals.Names(); len(req.Sg) == 0 {
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
		rules.Rules.Insert(rule.ID(), &rule)
		sg := locals.At(rule.Sg)
		rules.SGs.Insert(sg.Name, sg)
	}
	return nil
}

// Load get sg-sg-ie-icmp rules from local SG(s)
func (rules *SgIeSgIcmpRules) Load(ctx context.Context, client SGClient, locals SGs) (err error) {
	const api = "SgIeSgIcmpRules/Load"

	defer func() {
		err = errors.WithMessage(err, api)
	}()
	rules.SGs.Clear()
	rules.Rules.Clear()
	var req sgAPI.FindIESgSgIcmpRulesReq
	var resp *sgAPI.IESgSgIcmpRulesResp
	if req.SgLocal = locals.Names(); len(req.SgLocal) == 0 {
		return nil
	}
	if resp, err = client.FindIESgSgIcmpRules(ctx, &req); err != nil {
		return err
	}
	var nonLocalSgs []string
	for _, protoRule := range resp.GetRules() {
		var rule model.IESgSgIcmpRule
		if rule, err = conv.Proto2ModelIESgSgIcmpRule(protoRule); err != nil {
			return err
		}
		rules.Rules.Insert(rule.ID(), &rule)
		for _, sgN := range []string{rule.SgLocal, rule.Sg} {
			if sg := locals.At(sgN); sg != nil {
				_ = rules.SGs.Insert(sgN, sg)
			} else {
				nonLocalSgs = append(nonLocalSgs, sgN)
			}
		}
	}
	return rules.SGs.LoadFromNames(ctx, client, nonLocalSgs)
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
