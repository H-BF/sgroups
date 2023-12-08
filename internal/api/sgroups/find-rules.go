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

// FindRules impl SecGroupServiceServer
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
			return errors.WithMessagef(e, "convert SGRule '%s' to proto", rule.ID)
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

// FindFqdnRules impl SecGroupServiceServer
func (srv *sgService) FindFqdnRules(ctx context.Context, req *sg.FindFqdnRulesReq) (resp *sg.FqdnRulesResp, err error) {
	defer func() {
		err = correctError(err)
	}()
	var reader registry.Reader
	if reader, err = srv.registryReader(ctx); err != nil {
		return nil, err
	}
	defer reader.Close() //lint:nolint
	var sc registry.Scope = registry.NoScope
	if s := req.GetSgFrom(); len(s) > 0 {
		sc = registry.SGFrom(s[0], s[1:]...)
	}
	resp = new(sg.FqdnRulesResp)
	err = reader.ListFqdnRules(ctx, func(rule model.FQDNRule) error {
		r, e := sgFqdnRule2proto(rule)
		if e != nil {
			return errors.WithMessagef(e, "convert FQDNRule '%s' to proto", rule.ID)
		}
		resp.Rules = append(resp.Rules, r)
		return nil
	}, sc)
	if err != nil {
		return nil,
			status.Errorf(codes.Internal, "reason: %v", err)
	}
	return resp, nil
}

// FindSgIcmpRules impl SecGroupServiceServer
func (srv *sgService) FindSgIcmpRules(ctx context.Context, req *sg.FindSgIcmpRulesReq) (resp *sg.SgIcmpRulesResp, err error) {
	defer func() {
		err = correctError(err)
	}()
	var reader registry.Reader
	if reader, err = srv.registryReader(ctx); err != nil {
		return nil, err
	}
	defer reader.Close() //lint:nolint
	var sc registry.Scope = registry.NoScope
	if sgs := req.GetSg(); len(sgs) > 0 {
		sc = registry.SG(sgs...)
	}
	resp = new(sg.SgIcmpRulesResp)
	err = reader.ListSgIcmpRules(ctx, func(rule model.SgIcmpRule) error {
		r, e := sgIcmpRule2proto(rule)
		if e == nil {
			resp.Rules = append(resp.Rules, r)
		}
		return errors.WithMessagef(e, "convert SgIcmpRule '%s' to proto", rule.ID())
	}, sc)
	if err != nil {
		return nil,
			status.Errorf(codes.Internal, "reason: %v", err)
	}
	return resp, nil
}

// FindSgSgIcmpRules impl SecGroupServiceServer
func (srv *sgService) FindSgSgIcmpRules(ctx context.Context, req *sg.FindSgSgIcmpRulesReq) (resp *sg.SgSgIcmpRulesResp, err error) {
	defer func() {
		err = correctError(err)
	}()
	var reader registry.Reader
	if reader, err = srv.registryReader(ctx); err != nil {
		return nil, err
	}
	defer reader.Close() //lint:nolint
	var sc1, sc2 registry.Scope = registry.NoScope, registry.NoScope
	if sgs := req.GetSgFrom(); len(sgs) > 0 {
		sc1 = registry.SGFrom(sgs[0], sgs[1:]...)
	}
	if sgs := req.GetSgTo(); len(sgs) > 0 {
		sc2 = registry.SGTo(sgs[0], sgs[1:]...)
	}
	resp = new(sg.SgSgIcmpRulesResp)
	err = reader.ListSgSgIcmpRules(ctx, func(rule model.SgSgIcmpRule) error {
		r, e := sgSgIcmpRule2proto(rule)
		if e == nil {
			resp.Rules = append(resp.Rules, r)
		}
		return errors.WithMessagef(e, "convert SgSgIcmpRule '%s' to proto", rule.ID())
	}, registry.And(sc1, sc2))
	if err != nil {
		return nil,
			status.Errorf(codes.Internal, "reason: %v", err)
	}
	return resp, nil
}

// FindCidrSgRules impl SecGroupServiceServer
func (srv *sgService) FindCidrSgRules(ctx context.Context, req *sg.FindCidrSgRulesReq) (resp *sg.CidrSgRulesResp, err error) {
	defer func() {
		err = correctError(err)
	}()
	var reader registry.Reader
	if reader, err = srv.registryReader(ctx); err != nil {
		return nil, err
	}
	defer reader.Close() //lint:nolint
	var sc registry.Scope = registry.NoScope
	if sgs := req.GetSg(); len(sgs) > 0 {
		sc = registry.SG(sgs...)
	}
	resp = new(sg.CidrSgRulesResp)
	err = reader.ListCidrSgRules(ctx, func(r model.CidrSgRule) error {
		p, e := cidrSgRule2proto(r)
		if e == nil {
			resp.Rules = append(resp.Rules, p)
		}
		return errors.WithMessagef(e, "convert CidrSgRule '%s' to proto", r.ID)
	}, sc)
	return resp, err
}
