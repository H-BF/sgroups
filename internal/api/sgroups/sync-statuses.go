package sgroups

import (
	"sync/atomic"
	"time"

	"github.com/H-BF/sgroups/v2/internal/domains/sgroups"
	"github.com/H-BF/sgroups/v2/internal/patterns"
	registry "github.com/H-BF/sgroups/v2/internal/registry/sgroups"

	sg "github.com/H-BF/protos/pkg/api/sgroups"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// SyncStatuses impl sgService
func (srv *sgService) SyncStatuses(_ *emptypb.Empty, stream sg.SecGroupService_SyncStatusesServer) (err error) {
	const (
		updatePeriod = 3 * time.Second //TODO: In future move 'updatePeriod' onto config
	)

	defer func() {
		err = correctError(err)
	}()

	var commitCount int64
	var prevState *sgroups.SyncStatus
	commitCounter := func(_ patterns.EventType) {
		atomic.AddInt64(&commitCount, 1)
	}
	if subj := srv.reg.Subject(); subj != nil {
		obs := patterns.NewObserver(commitCounter, true, registry.DBUpdated{})
		subj.ObserversAttach(obs)
		defer subj.ObserversDetach(obs)
	}
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
