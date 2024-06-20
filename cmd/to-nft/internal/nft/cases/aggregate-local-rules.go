package cases

import (
	"context"

	conv "github.com/H-BF/sgroups/internal/api/sgroups"
	model "github.com/H-BF/sgroups/internal/domains/sgroups"

	"github.com/H-BF/corlib/pkg/dict"
	sgAPI "github.com/H-BF/protos/pkg/api/sgroups"
	"github.com/pkg/errors"
)

// SG2SGRules -
type SG2SGRules struct {
	Rules dict.HDict[model.SGRuleIdentity, *model.SGRule]
}

// IsEq -
func (rules *SG2SGRules) IsEq(other SG2SGRules) bool {
	return rules.Rules.Eq(&other.Rules, func(vL, vR *model.SGRule) bool {
		return vL.IsEq(*vR)
	})
}

// Load ...
func (rules *SG2SGRules) Load(ctx context.Context, client SGClient, locals SGs) (err error) {
	const api = "sg-rules/Load"

	defer func() {
		err = errors.WithMessage(err, api)
	}()

	localSgNames := locals.Names()
	if len(localSgNames) == 0 {
		return nil
	}
	reqs := []sgAPI.FindSgSgRulesReq{
		{SgFrom: localSgNames}, {SgTo: localSgNames},
	}
	for i := range reqs {
		var resp *sgAPI.SgSgRulesResp
		if resp, err = client.FindSgSgRules(ctx, &reqs[i]); err != nil {
			return err
		}
		for _, protoRule := range resp.GetRules() {
			var rule model.SGRule
			if rule, err = conv.Proto2ModelSGRule(protoRule); err != nil {
				return err
			}
			_ = rules.Rules.Insert(rule.ID, &rule)
		}
	}
	return nil
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
