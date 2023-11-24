package sgroups

import (
	"context"

	"github.com/H-BF/sgroups/internal/app"
	"github.com/H-BF/sgroups/internal/models/sgroups"

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

	var st *sgroups.SyncStatus
	st, err = srv.getSyncStatus(ctx)
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

func (srv *sgService) getSyncStatus(ctx context.Context) (*sgroups.SyncStatus, error) {
	reader, err := srv.registryReader(ctx)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = reader.Close()
	}()

	return reader.GetSyncStatus(ctx)
}

// OnStart -
func (srv *sgService) OnStart() {
	app.SetHealthState(true)
}

// OnStop -
func (srv *sgService) OnStop() {
	app.SetHealthState(false)
}
