package resources

import (
	"context"

	conv "github.com/H-BF/sgroups/internal/api/sgroups"
	model "github.com/H-BF/sgroups/internal/domains/sgroups"

	"github.com/H-BF/corlib/pkg/dict"
	sgAPI "github.com/H-BF/protos/pkg/api/sgroups"
	"github.com/pkg/errors"
)

// IECidrSgIcmpRules -
type IECidrSgIcmpRules struct {
	Rules dict.RBDict[model.IECidrSgIcmpRuleID, *model.IECidrSgIcmpRule]
}

// IsEq -
func (o IECidrSgIcmpRules) IsEq(other IECidrSgIcmpRules) bool {
	return o.Rules.Eq(&other.Rules, func(vL, vR *model.IECidrSgIcmpRule) bool {
		return vL.IsEq(*vR)
	})
}

// GetRulesForTrafficAndSG -
func (rules *IECidrSgIcmpRules) GetRulesForTrafficAndSG(tr model.Traffic, sg string) (ret []*model.IECidrSgIcmpRule) {
	rules.Rules.Iterate(func(_ model.IECidrSgIcmpRuleID, r *model.IECidrSgIcmpRule) bool {
		if r.SG == sg && r.Traffic == tr {
			ret = append(ret, r)
		}
		return true
	})
	return ret
}

// Load -
func (rules *IECidrSgIcmpRules) Load(ctx context.Context, client SGClient, locals SGs) (err error) {
	const api = "ie-cidr-sg-icmp-rules/Load"

	defer func() {
		err = errors.WithMessage(err, api)
	}()

	localSgNames := locals.Names()
	if len(localSgNames) == 0 {
		return nil
	}
	req := sgAPI.FindIECidrSgIcmpRulesReq{SG: localSgNames}
	var resp *sgAPI.IECidrSgIcmpRulesResp
	if resp, err = client.FindIECidrSgIcmpRules(ctx, &req); err != nil {
		return err
	}
	for _, protoRule := range resp.GetRules() {
		var rule model.IECidrSgIcmpRule
		if rule, err = conv.Proto2ModelIECidrSgIcmpRule(protoRule); err != nil {
			return err
		}
		_ = rules.Rules.Insert(rule.ID(), &rule)
	}
	return nil
}
