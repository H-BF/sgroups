package sgroups

import (
	"context"

	sg "github.com/H-BF/protos/pkg/api/sgroups"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

func (srv *sgService) Sync(ctx context.Context, req *sg.SyncReq) (ret *emptypb.Empty, err error) {
	ret = new(emptypb.Empty)
	defer func() {
		err = correctError(err)
	}()
	srv.registryWriter()
	ops := req.GetSyncOp()
	switch sbj := req.GetSubject().(type) {
	case *sg.SyncReq_Networks:
		nws := sbj.Networks.GetNetworks()
		err = syncNetworks{srv: srv, networks: nws, ops: ops}.
			process(ctx)
	case *sg.SyncReq_Groups:
		groups := sbj.Groups.GetGroups()
		err = syncGroups{srv: srv, ops: ops, groups: groups}.
			process(ctx)
	case *sg.SyncReq_SgRules:
		rules := sbj.SgRules.GetRules()
		err = syncRules{srv: srv, ops: ops, rules: rules}.
			process(ctx)
	default:
		err = status.Error(codes.InvalidArgument, "unsupported type subject")
	}
	return
}
