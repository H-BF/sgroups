package sgroups

import (
	"context"
	"github.com/H-BF/corlib/pkg/ranges"
	"github.com/H-BF/protos/pkg/api/common"
	sg "github.com/H-BF/protos/pkg/api/sgroups"
	model "github.com/H-BF/sgroups/internal/models/sgroups"
	registry "github.com/H-BF/sgroups/internal/registry/sgroups"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type syncRules struct {
	srv   *sgService
	rules []*sg.Rule
	ops   sg.SyncReq_SyncOp
}

func (snc syncRules) process(ctx context.Context) error {
	rules := make([]model.SGRule, 0, len(snc.rules))
	for _, rl := range snc.rules {
		var item model.SGRule
		err := sgRule{SGRule: &item}.from(rl)
		if err != nil {
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
	writer := snc.srv.registryWriter()
	return writer.SyncSGRules(ctx, rules, sc, opts...)
}

type portsRange struct {
	*model.PortRanges
}

type sgRule struct {
	*model.SGRule
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
	fct := ranges.IntsFactory(model.PortNumber(0))
	for _, s := range src {
		rgs = append(rgs,
			fct.Range(s.GetFrom(), false, s.GetTo(), false))
	}
	x := ranges.NewMultiRange(fct)
	x.Update(ranges.CombineMerge, rgs...)
	*r.PortRanges = x
}

func (r sgRule) from(src *sg.Rule) error {
	r.SgFrom.Name = src.GetSgFrom().GetName()
	r.SgTo.Name = src.GetSgFrom().GetName()
	err := networkTransport{NetworkTransport: &r.Transport}.
		from(src.GetTransport())
	if err != nil {
		return err
	}
	portsRange{PortRanges: &r.PortsFrom}.from(src.GetPortsFrom())
	portsRange{PortRanges: &r.PortsTo}.from(src.GetPortsTo())
	return nil
}
