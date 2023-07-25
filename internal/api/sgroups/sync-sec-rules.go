package sgroups

import (
	"context"

	model "github.com/H-BF/sgroups/internal/models/sgroups"
	registry "github.com/H-BF/sgroups/internal/registry/sgroups"

	"github.com/H-BF/protos/pkg/api/common"
	sg "github.com/H-BF/protos/pkg/api/sgroups"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type syncRules struct {
	wr    registry.Writer
	rules []*sg.Rule
	ops   sg.SyncReq_SyncOp
}

func (snc syncRules) process(ctx context.Context) error {
	rules := make([]model.SGRule, 0, len(snc.rules))
	for _, rl := range snc.rules {
		var item model.SGRule
		if err := (sgRule{SGRule: &item}).from(rl); err != nil {
			return status.Error(codes.InvalidArgument, err.Error())
		}
		rules = append(rules, item)
	}
	var opts []registry.Option
	if err := syncOptionsFromProto(snc.ops, &opts); err != nil {
		return status.Error(codes.InvalidArgument, err.Error())
	}
	var sc registry.Scope = registry.NoScope
	if snc.ops == sg.SyncReq_Delete {
		sc = registry.SGRule(rules...)
		rules = nil
	}
	return snc.wr.SyncSGRules(ctx, rules, sc, opts...)
}

type rulePorts []model.SGRulePorts

type sgRule struct {
	*model.SGRule
}

type sgRuleIdentity struct {
	*model.SGRuleIdentity
}

type networkTransport struct {
	*model.NetworkTransport
}

func (nt networkTransport) from(src common.Networks_NetIP_Transport) error {
	switch src {
	case common.Networks_NetIP_TCP:
		*nt.NetworkTransport = model.TCP
	case common.Networks_NetIP_UDP:
		*nt.NetworkTransport = model.UDP
	default:
		return status.Errorf(codes.InvalidArgument,
			"bad network transport (%v)", src)
	}
	return nil
}

func (r *rulePorts) from(src []*sg.Rule_Ports) error {
	for _, p := range src {
		var item model.SGRulePorts
		var e error
		if item.S, e = model.PortSource(p.S).ToPortRanges(); e != nil {
			return e
		}
		if item.D, e = model.PortSource(p.D).ToPortRanges(); e != nil {
			return e
		}
		*r = append(*r, item)
	}
	return nil
}

func (ri sgRuleIdentity) from(src *sg.Rule) error {
	ri.SgFrom.Name = src.GetSgFrom()
	ri.SgTo.Name = src.GetSgTo()
	return networkTransport{NetworkTransport: &ri.Transport}.
		from(src.GetTransport())
}

func (r sgRule) from(src *sg.Rule) error {
	err := sgRuleIdentity{SGRuleIdentity: &r.SGRuleIdentity}.
		from(src)
	if err == nil {
		var p rulePorts
		if err = p.from(src.GetPorts()); err == nil {
			r.Ports = p
		}
	}
	return err
}
