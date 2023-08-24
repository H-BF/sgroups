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

func sgAccPorts2proto(src []model.SGRulePorts) ([]*sg.AccPorts, error) {
	ret := make([]*sg.AccPorts, 0, len(src))
	for _, p := range src {
		var s, d model.PortSource
		if err := s.FromPortRanges(p.S); err != nil {
			return nil, errors.Wrapf(err, "bad 'S' ports value '%s'", p.S)
		}
		if err := d.FromPortRanges(p.D); err != nil {
			return nil, errors.Wrapf(err, "bad 'D' ports value '%s'", p.D)
		}
		ret = append(ret, &sg.AccPorts{S: string(s), D: string(d)})
	}
	return ret, nil

}

func sgRule2proto(src model.SGRule) (*sg.Rule, error) {
	var ret sg.Rule
	if t, e := netTranport2proto(src.ID.Transport); e != nil {
		return nil, e
	} else {
		ret.Transport = t
	}
	ret.Logs = src.Logs
	ret.SgFrom = src.ID.SgFrom
	ret.SgTo = src.ID.SgTo
	var e error
	ret.Ports, e = sgAccPorts2proto(src.Ports)
	return &ret, e
}

func sgFdqnRule2proto(src model.FDQNRule) (*sg.FdqnRule, error) {
	var ret sg.FdqnRule
	if t, e := netTranport2proto(src.ID.Transport); e != nil {
		return nil, e
	} else {
		ret.Transport = t
	}
	ret.Logs = src.Logs
	ret.SgFrom = src.ID.SgFrom
	var e error
	ret.Ports, e = sgAccPorts2proto(src.Ports)
	return &ret, e
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
			return errors.WithMessagef(e, "on convert SGRule '%s' to proto", rule.ID)
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
