package sgroups

import (
	"context"

	model "github.com/H-BF/sgroups/internal/models/sgroups"
	registry "github.com/H-BF/sgroups/internal/registry/sgroups"

	sg "github.com/H-BF/protos/pkg/api/sgroups"
	"github.com/pkg/errors"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (srv *sgService) FindRules(ctx context.Context, req *sg.FindRulesReq) (resp *sg.RulesResp, err error) {
	defer func() {
		err = correctError(err)
	}()
	var reader registry.Reader
	if reader, err = srv.registryReader(ctx); err != nil {
		return nil, err
	}
	defer reader.Close() //lint:nolint
	var sc1, sc2 registry.Scope = registry.NoScope, registry.NoScope
	if s := req.GetSgFrom(); len(s) > 0 {
		sc1 = registry.SGFrom(s[0], s[1:]...)
	}
	if s := req.GetSgTo(); len(s) > 0 {
		sc2 = registry.SGTo(s[0], s[1:]...)
	}
	resp = new(sg.RulesResp)
	err = reader.ListSGRules(ctx, func(rule model.SGRule) error {
		r, e := sgRule2proto(rule)
		if e != nil {
			return errors.WithMessagef(e, "convert SGRule '%s' to proto", rule)
		}
		resp.Rules = append(resp.Rules, r)
		return nil
	}, registry.And(sc1, sc2))
	if err != nil {
		return nil,
			status.Errorf(codes.Internal, "reason: %v", err)
	}
	return resp, nil
}
