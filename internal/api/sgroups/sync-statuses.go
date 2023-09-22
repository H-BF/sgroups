package sgroups

import (
	"sync/atomic"
	"time"

	"github.com/H-BF/sgroups/internal/models/sgroups"
	"github.com/H-BF/sgroups/internal/patterns"
	registry "github.com/H-BF/sgroups/internal/registry/sgroups"

	sg "github.com/H-BF/protos/pkg/api/sgroups"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// SyncStatuses impl sgService
func (srv *sgService) SyncStatuses(_ *emptypb.Empty, stream sg.SecGroupService_SyncStatusesServer) (err error) {
	defer func() {
		err = correctError(err)
	}()

	updatePeriod, _ := UpdatePeriod.Value(srv.appCtx)

	var commitCount int64
	var prevState *sgroups.SyncStatus
	commitCounter := func(_ patterns.EventType) {
		atomic.AddInt64(&commitCount, 1)
	}

	obs := patterns.NewObserver(commitCounter, true, registry.DBUpdated{})
	srv.reg.Subject().ObserversAttach(obs)
	defer srv.reg.Subject().ObserversDetach(obs)

	for ctx := stream.Context(); ; {
		if atomic.SwapInt64(&commitCount, 0) != 0 || prevState == nil {
			var newState *sgroups.SyncStatus
			if newState, err = srv.getSyncStatus(ctx); err != nil {
				return err
			}
			doSend := newState != nil &&
				(prevState == nil ||
					!newState.UpdatedAt.Equal(prevState.UpdatedAt))
			if doSend {
				resp := sg.SyncStatusResp{
					UpdatedAt: timestamppb.New(newState.UpdatedAt),
				}
				if err = stream.Send(&resp); err != nil {
					return nil
				}
				prevState = newState
			}
		}
		select {
		case <-srv.appCtx.Done():
			return errServiceIsClosing
		case <-ctx.Done():
			return nil
		case <-time.After(updatePeriod):
		}
	}
}
