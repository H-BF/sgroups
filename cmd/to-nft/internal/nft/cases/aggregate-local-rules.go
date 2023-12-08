package cases

import (
	"context"

	conv "github.com/H-BF/sgroups/internal/api/sgroups"
	"github.com/H-BF/sgroups/internal/dict"
	model "github.com/H-BF/sgroups/internal/models/sgroups"

	sgAPI "github.com/H-BF/protos/pkg/api/sgroups"
	"github.com/pkg/errors"
)

// SG2SGRules -
type SG2SGRules struct {
	SGs   SGs
	Rules dict.HDict[model.SGRuleIdentity, *model.SGRule]
}

// Load ...
func (rules *SG2SGRules) Load(ctx context.Context, client SGClient, locals SGs) (err error) {
	const api = "sg-rules/Load"

	defer func() {
		err = errors.WithMessage(err, api)
	}()

	rules.Rules.Clear()
	rules.SGs.Clear()
	localSgNames := locals.Names()
	if len(localSgNames) == 0 {
		return nil
	}
	reqs := []sgAPI.FindRulesReq{
		{SgFrom: localSgNames}, {SgTo: localSgNames},
	}
	var nonLocalSgs []string
	for i := range reqs {
		var resp *sgAPI.RulesResp
		if resp, err = client.FindRules(ctx, &reqs[i]); err != nil {
			return err
		}
		for _, protoRule := range resp.GetRules() {
			var rule model.SGRule
			if rule, err = conv.Proto2ModelSGRule(protoRule); err != nil {
				return err
			}
			_ = rules.Rules.Insert(rule.ID, &rule)
			for _, sgN := range []string{rule.ID.SgFrom, rule.ID.SgTo} {
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

// AllRules -
func (rules SG2SGRules) AllRules() []model.SGRule {
	var ret []model.SGRule
	rules.Rules.Iterate(func(_ model.SGRuleIdentity, v *model.SGRule) bool {
		ret = append(ret, *v)
		return true
	})
	return ret
}

// In -
func (rules SG2SGRules) In(sgTo string) (ret []model.SGRule) { //nolint:dupl
	rules.Rules.Iterate(func(k model.SGRuleIdentity, v *model.SGRule) bool {
		if k.SgTo == sgTo {
			ret = append(ret, *v)
		}
		return true
	})
	return ret
}

// Out -
func (rules SG2SGRules) Out(sgFrom string) (ret []model.SGRule) { //nolint:dupl
	rules.Rules.Iterate(func(k model.SGRuleIdentity, v *model.SGRule) bool {
		if k.SgFrom == sgFrom {
			ret = append(ret, *v)
		}
		return true
	})
	return ret
}
