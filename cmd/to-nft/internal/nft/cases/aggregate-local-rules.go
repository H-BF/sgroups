package cases

import (
	"context"
	"net"

	sgAPI "github.com/H-BF/protos/pkg/api/sgroups"
	conv "github.com/H-BF/sgroups/internal/api/sgroups"
	model "github.com/H-BF/sgroups/internal/models/sgroups"

	"github.com/pkg/errors"
)

type (
	// SgFrom ...
	SgFrom = struct {
		SgName
		Transport model.NetworkTransport
	}
	// SgTo ...
	SgTo = map[SgName]RulePorts
	// SgRules ...
	SgRules = map[SgFrom]SgTo

	// RulePorts ...
	RulePorts = struct {
		From, To model.PortRanges
	}

	// LocalRules ...
	LocalRules struct {
		SgRules
		LocalSGs LocalSGs
		UsedSGs  map[SgName]SG
	}

	// SgNetworks ...
	SgNetworks = struct {
		V4, V6 []net.IPNet
	}

	// Sg2Networks ...
	Sg2Networks map[SgName]*SgNetworks
)

// Load ...
func (rules *LocalRules) Load(ctx context.Context, client SGClient, locals LocalSGs) error {
	const api = "LocalRules/Load"

	rules.SgRules = make(SgRules)
	rules.LocalSGs = make(LocalSGs)
	rules.UsedSGs = make(map[SgName]SG)

	localSgNames := locals.Names()
	if len(localSgNames) == 0 {
		return nil
	}
	reqs := []sgAPI.FindRulesReq{
		{SgFrom: localSgNames}, {SgTo: localSgNames},
	}
	for i := range reqs {
		req, isFrom := &reqs[i], i == 0
		resp, err := client.FindRules(ctx, req)
		if err != nil {
			return errors.WithMessage(err, api)
		}
		for _, protoRule := range resp.GetRules() {
			var rule model.SGRule
			if rule, err = conv.Proto2ModelSGRule(protoRule); err != nil {
				return errors.WithMessage(err, api)
			}
			if loc := locals[rule.SgFrom.Name]; isFrom && loc != nil {
				rules.addRule(rule)
				rules.LocalSGs[rule.SgFrom.Name] = loc
			} else if loc := locals[rule.SgTo.Name]; !isFrom && loc != nil {
				rules.addRule(rule)
				rules.LocalSGs[rule.SgTo.Name] = loc
			} else {
				continue
			}
			rules.UsedSGs[rule.SgFrom.Name] = rule.SgFrom
			rules.UsedSGs[rule.SgTo.Name] = rule.SgTo
		}
	}
	return nil
}

func (rules *LocalRules) addRule(rule model.SGRule) {
	sgFrom := SgFrom{
		Transport: rule.Transport,
		SgName:    rule.SgFrom.Name,
	}
	sgTo := rules.SgRules[sgFrom]
	if sgTo == nil {
		sgTo = make(SgTo)
		rules.SgRules[sgFrom] = sgTo
	}
	sgTo[rule.SgTo.Name] = RulePorts{
		From: rule.PortsFrom,
		To:   rule.PortsTo,
	}
}

// IterateNetworks ...
func (rules LocalRules) IterateNetworks(f func(sgName string, nets []net.IPNet, isV6 bool) error) error {
	type tk = struct {
		sgName string
		v6     bool
	}
	var sg2nws Sg2Networks
	sg2nws.Init(rules)
	seen := make(map[tk]bool)
	send := func(sgName string, isV6 bool, nets []net.IPNet) error {
		k := tk{sgName, isV6}
		if !seen[k] {
			seen[k] = true
			return f(sgName, nets, isV6)
		}
		return nil
	}
	for from, to := range rules.SgRules {
		nw1 := sg2nws[from.SgName]
		for toSg := range to {
			nw2 := sg2nws[toSg]
			if len(nw1.V4) > 0 && len(nw2.V4) > 0 {
				err := send(from.SgName, false, nw1.V4)
				if err == nil {
					err = send(toSg, false, nw2.V4)
				}
				if err != nil {
					return err
				}
			}
			if len(nw1.V6) > 0 && len(nw2.V6) > 0 {
				err := send(from.SgName, true, nw1.V6)
				if err == nil {
					err = send(toSg, true, nw2.V6)
				}
				if err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// TemplatesOut ...
func (rules LocalRules) TemplatesOut(f func(tr model.NetworkTransport, out string, in []string) error) error {
	for from, to := range rules.SgRules {
		if rules.LocalSGs[from.SgName] != nil {
			var in []string
			for toSg := range to {
				in = append(in, toSg)
			}
			if e := f(from.Transport, from.SgName, in); e != nil {
				return e
			}
		}
	}
	return nil
}

// TemplatesIn ...
func (rules LocalRules) TemplatesIn(f func(tr model.NetworkTransport, in []string, out string) error) error {
	data := make(map[SgFrom][]string)
	for from, to := range rules.SgRules {
		for toSg := range to {
			if rules.LocalSGs[toSg] != nil {
				k := SgFrom{SgName: from.SgName, Transport: from.Transport}
				data[k] = append(data[k], toSg)
			}
		}
	}
	for in, out := range data {
		if e := f(in.Transport, out, in.SgName); e != nil {
			return e
		}
	}
	return nil
}

// Init ...
func (sg2nws *Sg2Networks) Init(locals LocalRules) {
	*sg2nws = make(Sg2Networks)
	for _, sg := range locals.UsedSGs {
		var nws SgNetworks
		nws.V4, nws.V6 = separateNetworks(sg.Networks)
		(*sg2nws)[sg.Name] = &nws
	}
}
