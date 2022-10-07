package sgroups

import (
	"context"

	sg "github.com/H-BF/protos/pkg/api/sgroups"
	model "github.com/H-BF/sgroups/internal/models/sgroups"
	registry "github.com/H-BF/sgroups/internal/registry/sgroups"
	"github.com/pkg/errors"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (srv *sgService) FindRules(ctx context.Context, req *sg.FindRulesReq) (resp *sg.RulesResp, err error) {
	reader := srv.registryReader()
	defer func() {
		err = correctError(err)
	}()
	var sc1, sc2 registry.Scope = registry.NoScope, registry.NoScope
	if s := req.GetSgFrom(); len(s) > 0 {
		sc1 = registry.SGFrom(s[0], s[1:]...)
		sc2 = registry.Not(registry.NoScope)
	}
	if s := req.GetSgTo(); len(s) > 0 {
		sc2 = registry.SGTo(s[0], s[1:]...)
		if sc1 == registry.NoScope {
			sc1 = registry.Not(registry.NoScope)
		}
	}
	resp = new(sg.RulesResp)
	err = reader.ListSGRules(ctx, func(rule model.SGRule) error {
		r, e := sgRule2proto(rule)
		if e != nil {
			return errors.WithMessage(e, "on convert SGRule to proto")
		}
		resp.Rules = append(resp.Rules, &r)
		return errSuccess
	}, registry.Or(sc1, sc2))
	if err != nil && !errors.Is(err, errSuccess) {
		return nil,
			status.Errorf(codes.Internal, "reason: %v", err)
	}
	return resp, nil
}
