package sgroups

import (
	"context"

	model "github.com/H-BF/sgroups/internal/models/sgroups"
	registry "github.com/H-BF/sgroups/internal/registry/sgroups"

	"github.com/H-BF/corlib/pkg/ranges"
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
			return err
		}
		rules = append(rules, item)
	}
	var opts []registry.Option
	if err := syncOptionsFromProto(snc.ops, &opts); err != nil {
		return err
	}
	var sc registry.Scope = registry.NoScope
	if snc.ops != sg.SyncReq_FullSync {
		sc = registry.SGRule(rules...)
	}
	if snc.ops == sg.SyncReq_Delete {
		rules = rules[:0]
	}
	return snc.wr.SyncSGRules(ctx, rules, sc, opts...)
}

type portsRange struct {
	*model.PortRanges
}

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

func (r portsRange) from(src []*common.Networks_NetIP_PortRange) {
	rgs := make([]model.PortRange, 0, len(src))
	for _, s := range src {
		rgs = append(rgs,
			model.PortRangeFactory.Range(s.GetFrom(), false, s.GetTo(), false))
	}
	x := ranges.NewMultiRange(model.PortRangeFactory)
	x.Update(ranges.CombineMerge, rgs...)
	*r.PortRanges = x
}

func (ri sgRuleIdentity) from(src *sg.Rule) error {
	ri.SgFrom.Name = src.GetSgFrom().GetName()
	ri.SgTo.Name = src.GetSgTo().GetName()
	return networkTransport{NetworkTransport: &ri.Transport}.
		from(src.GetTransport())
}

func (r sgRule) from(src *sg.Rule) error {
	err := sgRuleIdentity{SGRuleIdentity: &r.SGRuleIdentity}.
		from(src)
	if err == nil {
		portsRange{PortRanges: &r.PortsFrom}.from(src.GetPortsFrom())
		portsRange{PortRanges: &r.PortsTo}.from(src.GetPortsTo())
	}
	return err
}
