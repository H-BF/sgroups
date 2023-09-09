package cases

import (
	"context"
	"net"
	"sync"

	conv "github.com/H-BF/sgroups/internal/api/sgroups"
	model "github.com/H-BF/sgroups/internal/models/sgroups"

	"github.com/H-BF/corlib/pkg/parallel"
	sgAPI "github.com/H-BF/protos/pkg/api/sgroups"
	"github.com/ahmetb/go-linq/v3"
	"github.com/pkg/errors"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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
		SGs
		In       []model.SGRule
		Out      []model.SGRule
		Networks Sg2Networks
	}

	// SgNetworks -
	SgNetworks struct {
		V4, V6 []net.IPNet
	}

	// Sg2Networks -
	Sg2Networks map[SgName]*SgNetworks
)

// Load ...
func (rules *SG2SGRules) Load(ctx context.Context, client SGClient, locals SGs) (err error) {
	const api = "LocalRules/Load"

	defer func() {
		err = errors.WithMessage(err, api)
	}()

	localSgNames := locals.Names()
	if len(localSgNames) == 0 {
		return nil
	}
	rules.Networks = nil
	rules.In = nil
	rules.Out = nil
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
			*dest[i] = append(*dest[i], rule)
		}
	}
	if err = rules.SGs.LoadFromRules(ctx, client, append(rules.In, rules.Out...)); err == nil {
		err = rules.Networks.Load(ctx, client, rules.SGs.Names())
	}
	return err
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

// IterateNetworks ...
func (rules SG2SGRules) IterateNetworks(f func(sgName string, nets []net.IPNet, isV6 bool) error) error {
	var err error
	type item = struct {
		sg string
		nw *SgNetworks
	}
	linq.From(append(rules.In, rules.Out...)).
		SelectMany(func(i any) linq.Query {
			r := i.(model.SGRule)
			return linq.From([...]item{
				{sg: r.ID.SgFrom, nw: rules.Networks[r.ID.SgFrom]},
				{sg: r.ID.SgTo, nw: rules.Networks[r.ID.SgTo]},
			})
		}).
		Where(func(i any) bool {
			return i.(item).nw != nil
		}).
		DistinctBy(func(i any) any {
			return i.(item).sg
		}).
		ForEach(func(i any) {
			if err == nil {
				v := i.(item)
				if len(v.nw.V4) > 0 {
					err = f(v.sg, v.nw.V4, false)
				}
				if err == nil && len(v.nw.V6) > 0 {
					err = f(v.sg, v.nw.V6, true)
				}
			}
		})
	return err
}

// TemplatesOutRules -
func (rules SG2SGRules) TemplatesOutRules() []RulesOutTemplate { //nolint:dupl
	type groupped = struct {
		Sg    string
		Proto model.NetworkTransport
	}
	var res []RulesOutTemplate
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
			return rules.SGs[v.Key.(string)] != nil
		}).
		Select(func(i any) any {
			v := i.(linq.Group)
			item := RulesOutTemplate{
				SgOut: rules.SGs[v.Key.(string)].SecurityGroup,
			}
			for _, g := range v.Group {
				item.In = append(item.In, g.(groupped))
			}
			return item
		}).ToSlice(&res)
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
			return rules.SGs[v.Key.(string)] != nil
		}).
		Select(func(i any) any {
			v := i.(linq.Group)
			item := RulesInTemplate{
				SgIn: rules.SGs[v.Key.(string)].SecurityGroup,
			}
			for _, g := range v.Group {
				item.Out = append(item.Out, g.(groupped))
			}
			return item
		}).ToSlice(&res)
	return res
}

// Load loads networks from db
func (sg2nws *Sg2Networks) Load(ctx context.Context, client SGClient, sgNames []SgName) error {
	*sg2nws = make(Sg2Networks)
	var mx sync.Mutex
	err := parallel.ExecAbstract(len(sgNames), 8, func(i int) error { //nolint:gomnd
		rq := sgAPI.GetSgSubnetsReq{SgName: sgNames[i]}
		resp, e := client.GetSgSubnets(ctx, &rq)
		if e != nil {
			if status.Code(errors.Cause(e)) == codes.NotFound {
				return nil
			}
			return e
		}
		nws := make([]Network, 0, len(resp.GetNetworks()))
		for _, nw := range resp.GetNetworks() {
			var m model.Network
			if m, e = conv.Proto2ModelNetwork(nw); e != nil {
				return e
			}
			nws = append(nws, m)
		}
		var x SgNetworks
		x.V4, x.V6 = SeparateNetworks(nws)
		mx.Lock()
		(*sg2nws)[sgNames[i]] = &x
		mx.Unlock()
		return nil
	})

	return err
}
