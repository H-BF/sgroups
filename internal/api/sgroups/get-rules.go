package sgroups

import (
	"context"

	model "github.com/H-BF/sgroups/internal/models/sgroups"
	registry "github.com/H-BF/sgroups/internal/registry/sgroups"

	"github.com/H-BF/protos/pkg/api/common"
	sg "github.com/H-BF/protos/pkg/api/sgroups"
	"github.com/pkg/errors"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func netTranport2proto(src model.NetworkTransport) (common.Networks_NetIP_Transport, error) {
	switch src {
	case model.TCP:
		return common.Networks_NetIP_TCP, nil
	case model.UDP:
		return common.Networks_NetIP_UDP, nil
	}
	return 0, errors.Errorf("bad net transport (%v)", src)
}

func sgRule2proto(src model.SGRule) (*sg.Rule, error) {
	var ret sg.Rule
	if t, e := netTranport2proto(src.Transport); e != nil {
		return nil, e
	} else {
		ret.Transport = t
	}
	ret.SgFrom = src.SgFrom.Name
	ret.SgTo = src.SgTo.Name
	ret.Ports = make([]*sg.Rule_Ports, 0, len(src.Ports))
	for _, p := range src.Ports {
		var s, d model.PortSource
		if err := s.FromPortRanges(p.S); err != nil {
			return nil, errors.Wrapf(err, "bad 'S' ports value '%s'", p.S)
		}
		if err := d.FromPortRanges(p.D); err != nil {
			return nil, errors.Wrapf(err, "bad 'D' ports value '%s'", p.D)
		}
		ret.Ports = append(ret.Ports, &sg.Rule_Ports{S: string(s), D: string(d)})
	}
	return &ret, nil
}

func (srv *sgService) GetRules(ctx context.Context, req *sg.GetRulesReq) (resp *sg.RulesResp, err error) {
	defer func() {
		err = correctError(err)
	}()
	var reader registry.Reader
	if reader, err = srv.registryReader(ctx); err != nil {
		return nil, err
	}
	defer reader.Close() //lint:nolint
	resp = new(sg.RulesResp)
	err = reader.ListSGRules(ctx, func(rule model.SGRule) error {
		r, e := sgRule2proto(rule)
		if e != nil {
			return errors.WithMessagef(e, "on convert SGRule '%s' to proto", rule)
		}
		resp.Rules = append(resp.Rules, r)
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
