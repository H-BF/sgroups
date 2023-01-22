package cases

import (
	"context"
	"sort"
	"strings"

	"github.com/H-BF/corlib/pkg/slice"
	sgAPI "github.com/H-BF/protos/pkg/api/sgroups"
	conv "github.com/H-BF/sgroups/internal/api/sgroups"
	model "github.com/H-BF/sgroups/internal/models/sgroups"
	"github.com/pkg/errors"
)

type (
	// AggSgRules SG rules list
	AggSgRules []model.SGRule

	aggSgRulesDedupKey struct {
		*model.SGRule
	}
)

// Load it loads AggSgRules from SG server
func (agg *AggSgRules) Load(ctx context.Context, client SGClient, from, to []SgName) error {
	const api = "AggSgRules/Load"

	req := &sgAPI.FindRulesReq{
		SgFrom: from,
		SgTo:   to,
	}
	resp, err := client.FindRules(ctx, req)
	if err != nil {
		return errors.WithMessage(err, api)
	}
	for _, srcRule := range resp.GetRules() {
		var rule model.SGRule
		if rule, err = conv.Proto2ModelSGRule(srcRule); err != nil {
			return errors.WithMessage(err, api)
		}
		*agg = append(*agg, rule)
	}
	return nil
}

// Dedup deduplicate rule(s) list
func (agg *AggSgRules) Dedup() {
	sort.Slice(*agg, func(i, j int) bool {
		return aggSgRulesDedupKey{&(*agg)[i]}.
			cmp(aggSgRulesDedupKey{&(*agg)[j]}) < 0
	})
	_ = slice.DedupSlice(agg, func(i, j int) bool {
		return aggSgRulesDedupKey{&(*agg)[i]}.
			cmp(aggSgRulesDedupKey{&(*agg)[j]}) == 0
	})
}

// UsedSGs it gets unique list of SG
func (agg AggSgRules) UsedSGs() []SG {
	ret := make([]SG, len(agg)*2)
	for _, r := range agg {
		ret = append(append(ret, r.SgFrom), r.SgTo)
	}
	sort.Slice(ret, func(i, j int) bool {
		l, r := ret[i], ret[j]
		return !strings.EqualFold(l.Name, r.Name) &&
			strings.Compare(l.Name, r.Name) < 0
	})
	_ = slice.DedupSlice(&ret, func(i, j int) bool {
		return strings.EqualFold(ret[i].Name, ret[j].Name)
	})
	return ret
}

func (k aggSgRulesDedupKey) cmp(o aggSgRulesDedupKey) int {
	funcs := []func() int{
		func() int {
			return int(k.Transport) - int(o.Transport)
		},
		func() int {
			if strings.EqualFold(k.SgFrom.Name, o.SgFrom.Name) {
				return 0
			}
			return strings.Compare(k.SgFrom.Name, o.SgFrom.Name)
		},
		func() int {
			if strings.EqualFold(k.SgTo.Name, o.SgTo.Name) {
				return 0
			}
			return strings.Compare(k.SgTo.Name, o.SgTo.Name)

		},
	}
	for _, f := range funcs {
		if d := f(); d != 0 {
			return d
		}
	}
	return 0
}
