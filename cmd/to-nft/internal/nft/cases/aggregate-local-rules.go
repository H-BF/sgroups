package cases

import (
	"context"

	conv "github.com/H-BF/sgroups/internal/api/sgroups"
	"github.com/H-BF/sgroups/internal/dict"
	model "github.com/H-BF/sgroups/internal/models/sgroups"

	sgAPI "github.com/H-BF/protos/pkg/api/sgroups"
	"github.com/ahmetb/go-linq/v3"
	"github.com/pkg/errors"
)

type (
	// RulesOutTempalte -
	RulesOutTemplate struct {
		SgOut model.SecurityGroup
		In    []struct {
			Sg    string
			Proto model.NetworkTransport
		}
	}
	// RulesOutTemplates = dict: SgNameFrom -> RulesOutTemplate
	RulesOutTemplates = dict.HDict[string, RulesOutTemplate]

	// RulesInTempalte -
	RulesInTemplate struct {
		SgIn model.SecurityGroup
		Out  []struct {
			Sg    string
			Proto model.NetworkTransport
		}
	}

	// SG2SGRules -
	SG2SGRules struct {
		SGs SGs
		In  []model.SGRule
		Out []model.SGRule
	}
)

// Load ...
func (rules *SG2SGRules) Load(ctx context.Context, client SGClient, locals SGs) (err error) {
	const api = "LocalRules/Load"

	defer func() {
		err = errors.WithMessage(err, api)
	}()

	rules.SGs.Clear()
	rules.In = nil
	rules.Out = nil
	localSgNames := locals.Names()
	if len(localSgNames) == 0 {
		return nil
	}
	reqs := []sgAPI.FindRulesReq{
		{SgFrom: localSgNames}, {SgTo: localSgNames},
	}
	dest := []*[]model.SGRule{
		&rules.Out, &rules.In,
	}
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
			sg1 := locals.At(rule.ID.SgFrom)
			sg2 := locals.At(rule.ID.SgTo)
			if sg1 != nil && sg2 != nil {
				*dest[i] = append(*dest[i], rule)
				_ = rules.SGs.Insert(sg1.Name, sg1)
				_ = rules.SGs.Insert(sg2.Name, sg2)
			}
		}
	}
	return nil
}

// AllRules -
func (rules SG2SGRules) AllRules() []model.SGRule {
	src := append(rules.In, rules.Out...)
	ret := src[:0]
	linq.From(src).DistinctBy(func(i any) any {
		type ri = struct {
			SgFrom, SgTo string
			Proto        model.NetworkTransport
		}
		v := i.(model.SGRule)
		return ri{
			SgFrom: v.ID.SgFrom,
			SgTo:   v.ID.SgTo,
			Proto:  v.ID.Transport,
		}
	}).ToSlice(&ret)
	return ret
}

// TemplatesOutRules -
func (rules SG2SGRules) TemplatesOutRules() RulesOutTemplates { //nolint:dupl
	type groupped = struct {
		Sg    string
		Proto model.NetworkTransport
	}
	var res RulesOutTemplates
	linq.From(rules.Out).
		GroupBy(
			func(i any) any {
				return i.(model.SGRule).ID.SgFrom
			},
			func(i any) any {
				r := i.(model.SGRule)
				return groupped{Sg: r.ID.SgTo, Proto: r.ID.Transport}
			},
		).
		Where(func(i any) bool {
			v := i.(linq.Group)
			return rules.SGs.At(v.Key.(string)) != nil
		}).
		ForEach(func(i any) {
			v := i.(linq.Group)
			item := RulesOutTemplate{
				SgOut: rules.SGs.At(v.Key.(string)).SecurityGroup,
			}
			for _, g := range v.Group {
				item.In = append(item.In, g.(groupped))
			}
			res.Put(item.SgOut.Name, item)
		})
	return res
}

// TemplatesInRules -
func (rules SG2SGRules) TemplatesInRules() []RulesInTemplate { //nolint:dupl
	type groupped = struct {
		Sg    string
		Proto model.NetworkTransport
	}
	var res []RulesInTemplate
	linq.From(rules.In).
		GroupBy(
			func(i any) any {
				return i.(model.SGRule).ID.SgTo
			},
			func(i any) any {
				r := i.(model.SGRule)
				return groupped{Sg: r.ID.SgFrom, Proto: r.ID.Transport}
			},
		).
		Where(func(i any) bool {
			v := i.(linq.Group)
			return rules.SGs.At(v.Key.(string)) != nil
		}).
		Select(func(i any) any {
			v := i.(linq.Group)
			item := RulesInTemplate{
				SgIn: rules.SGs.At(v.Key.(string)).SecurityGroup,
			}
			for _, g := range v.Group {
				item.Out = append(item.Out, g.(groupped))
			}
			return item
		}).ToSlice(&res)
	return res
}
