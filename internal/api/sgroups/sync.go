package sgroups

import (
	"context"

	sg "github.com/H-BF/protos/pkg/api/sgroups"
	registry "github.com/H-BF/sgroups/internal/registry/sgroups"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

//Sync impl service
func (srv *sgService) Sync(ctx context.Context, req *sg.SyncReq) (*emptypb.Empty, error) {
	ret := new(emptypb.Empty)
	var wr registry.Writer
	var err error
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
		err = syncNetworks{wr: wr, networks: nws, ops: ops}.
			process(ctx)
	case *sg.SyncReq_Groups:
		groups := sbj.Groups.GetGroups()
		err = syncGroups{wr: wr, ops: ops, groups: groups}.
			process(ctx)
	case *sg.SyncReq_SgRules:
		rules := sbj.SgRules.GetRules()
		err = syncRules{wr: wr, ops: ops, rules: rules}.
			process(ctx)
	default:
		err = status.Error(codes.InvalidArgument, "unsupported type subject")
	}
	return ret, err
}
