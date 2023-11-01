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
)

// Load get sg-sg-icmp rules from local SG(s)
func (rules *SgSgIcmpRules) Load(ctx context.Context, client SGClient, locals SGs) (err error) {
	const api = "SgSgIcmpRules/Load"

	//model.SgSgIcmpRuleID
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
