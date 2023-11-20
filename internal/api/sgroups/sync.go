package sgroups

import (
	"context"

	registry "github.com/H-BF/sgroups/internal/registry/sgroups"

	sg "github.com/H-BF/protos/pkg/api/sgroups"
	"github.com/pkg/errors"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
)

// Sync impl service
func (srv *sgService) Sync(ctx context.Context, req *sg.SyncReq) (ret *emptypb.Empty, err error) {
	ret = new(emptypb.Empty)
	var wr registry.Writer
	if wr, err = srv.registryWriter(ctx); err != nil {
		return ret, correctError(err)
	}
	defer func() {
		if err != nil {
			wr.Abort()
		} else {
			err = wr.Commit()
		}
		err = correctError(err)
	}()
	ops := req.GetSyncOp()
	switch sbj := req.GetSubject().(type) {
	case *sg.SyncReq_Networks:
		nws := sbj.Networks.GetNetworks()
		err = syncNetworks(ctx, wr.SyncNetworks, nws, ops)
	case *sg.SyncReq_Groups:
		groups := sbj.Groups.GetGroups()
		err = syncSecurityGroups(ctx, wr.SyncSecurityGroups, groups, ops)
	case *sg.SyncReq_SgRules:
		rules := sbj.SgRules.GetRules()
		err = syncSGRules(ctx, wr.SyncSGRules, rules, ops)
	case *sg.SyncReq_FqdnRules:
		rules := sbj.FqdnRules.GetRules()
		err = syncFQDNRules(ctx, wr.SyncFqdnRules, rules, ops)
	case *sg.SyncReq_SgIcmpRules:
		rules := sbj.SgIcmpRules.GetRules()
		err = syncSgIcmpRule(ctx, wr.SyncSgIcmpRules, rules, ops)
	case *sg.SyncReq_SgSgIcmpRules:
		rules := sbj.SgSgIcmpRules.GetRules()
		err = syncSgSgIcmpRule(ctx, wr.SyncSgSgIcmpRules, rules, ops)
	default:
		err = status.Error(codes.InvalidArgument, "sync unsupported subject type")
	}
	if errors.Is(err, registry.ErrValidate) {
		err = status.Errorf(codes.InvalidArgument, "%s", err.Error())
	}
	return ret, err
}

type syncerF[TModel any] func(context.Context, []TModel, registry.Scope, ...registry.Option) error

type syncAlg[TModel any, TProto proto.Message] struct {
	makePrimaryKeyScope func([]TModel) registry.Scope
	proto2model         func(TProto) (TModel, error)
}

func (hlp syncAlg[TModel, TProto]) process(ctx context.Context, snk syncerF[TModel], in []TProto, op sg.SyncReq_SyncOp) error {
	modelObjs := make([]TModel, len(in))
	var err error
	for i := range in {
		modelObjs[i], err = hlp.proto2model(in[i])
		if err != nil {
			return status.Error(codes.InvalidArgument, err.Error())
		}
	}
	var opts []registry.Option
	if opts, err = syncOptionsFromProto(op); err != nil {
		return err
	}
	var sc registry.Scope = registry.NoScope
	if op == sg.SyncReq_Delete {
		sc = hlp.makePrimaryKeyScope(modelObjs)
		modelObjs = nil
	}
	return snk(ctx, modelObjs, sc, opts...)
}

func syncOptionsFromProto(o sg.SyncReq_SyncOp) (ret []registry.Option, err error) {
	switch o {
	case sg.SyncReq_Upsert:
		ret = append(ret, registry.SyncOmitDelete{})
	case sg.SyncReq_Delete:
		ret = append(ret, registry.SyncOmitInsert{}, registry.SyncOmitUpdate{})
	case sg.SyncReq_FullSync:
	default:
		err = status.Error(codes.InvalidArgument, "unsupported sync option")
	}
	return ret, err
}
