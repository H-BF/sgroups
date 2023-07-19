package sgroups

import (
	"context"

	"github.com/H-BF/sgroups/internal/models/sgroups"
	registry "github.com/H-BF/sgroups/internal/registry/sgroups"

	sg "github.com/H-BF/protos/pkg/api/sgroups"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// SyncStatus impl SgService
func (srv *sgService) SyncStatus(ctx context.Context, _ *emptypb.Empty) (resp *sg.SyncStatusResp, err error) {
	defer func() {
		err = correctError(err)
	}()
	var reader registry.Reader
	if reader, err = srv.registryReader(ctx); err != nil {
		return nil, err
	}
	defer reader.Close() //lint:nolint
	var st *sgroups.SyncStatus
	st, err = reader.GetSyncStatus(ctx)
	if err != nil {
		return nil, err
	}
	if st == nil {
		return nil, status.Error(codes.NotFound, "no updates")
	}
	return &sg.SyncStatusResp{
		UpdatedAt: timestamppb.New(st.UpdatedAt),
	}, nil
}
