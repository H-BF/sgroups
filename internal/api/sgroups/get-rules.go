package sgroups

import (
	"context"

	"github.com/H-BF/protos/pkg/api/common"
	sg "github.com/H-BF/protos/pkg/api/sgroups"
	model "github.com/H-BF/sgroups/internal/models/sgroups"
	registry "github.com/H-BF/sgroups/internal/registry/sgroups"
	"github.com/pkg/errors"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

//nolint:nakedret
func sgRule2proto(src model.SGRule) (ret sg.Rule, err error) {
	switch a := src.Transport; a {
	case model.TCP:
		ret.Transport = common.Networks_NetIP_TCP
	case model.UDP:
		ret.Transport = common.Networks_NetIP_UDP
	default:
		err = errors.Errorf("bad net transport (%v)", a)
		return
	}
	ret.SgFrom, ret.SgTo = new(sg.SecGroup), new(sg.SecGroup)
	srcGroups := []*model.SecurityGroup{&src.SgFrom, &src.SgTo}
	dstGroups := []*sg.SecGroup{ret.SgFrom, ret.SgTo}
	for i := range srcGroups {
		gSrc, gDst := srcGroups[i], dstGroups[i]
		gDst.Name = gSrc.Name
		var dstNetworks []*sg.Network
		for _, srcNetwork := range gSrc.Networks {
			dstNetworks = append(dstNetworks,
				&sg.Network{
					Name: srcNetwork.Name,
					Network: &common.Networks_NetIP{
						CIDR: srcNetwork.Net.String(),
					},
				})
		}
		gDst.Networks = dstNetworks
	}
	portsSrc := []*model.PortRanges{&src.PortsFrom, &src.PortsTo}
	portsDst := []*[]*common.Networks_NetIP_PortRange{&ret.PortsFrom, &ret.PortsTo}
	for i := range portsSrc {
		portsSrc[i].Iterate(func(portRange model.PortRange) bool {
			var ex0 bool
			var ex1 bool
			var item common.Networks_NetIP_PortRange
			l, u := portRange.Bounds()
			item.From, ex0 = l.AsIncluded().GetValue()
			item.To, ex1 = u.AsIncluded().GetValue()
			if ex0 || ex1 {
				err = errors.New("bad port range")
				return false
			}
			d := portsDst[i]
			*d = append(*d, &item)
			return true
		})
	}
	return
}

func (srv *sgService) GetRules(ctx context.Context, req *sg.GetRulesReq) (resp *sg.RulesResp, err error) {
	defer func() {
		err = correctError(err)
	}()
	var reader registry.Reader
	if reader, err = srv.registryReader(ctx); err != nil {
		return nil, err
	}
	resp = new(sg.RulesResp)
	err = reader.ListSGRules(ctx, func(rule model.SGRule) error {
		r, e := sgRule2proto(rule)
		if e != nil {
			return errors.WithMessagef(e, "on convert SGRule '%s' to proto", rule)
		}
		resp.Rules = append(resp.Rules, &r)
		return nil
	}, registry.And(
		registry.SGFrom(req.GetSgFrom()), registry.SGTo(req.GetSgTo()),
	))
	if err != nil {
		return nil,
			status.Errorf(codes.Internal, "reason: %v", err)
	}
	if len(resp.GetRules()) == 0 {
		return nil,
			status.Errorf(codes.NotFound, "not found rules for from SG '%s' to SG '%s'",
				req.GetSgFrom(), req.GetSgTo())
	}
	return resp, nil
}
