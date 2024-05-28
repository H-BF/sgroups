package internal

import (
	"context"
	"sync"
	"time"

	sgAPI "github.com/H-BF/protos/pkg/api/sgroups"
	model "github.com/H-BF/sgroups/internal/models/sgroups"

	"github.com/H-BF/corlib/logger"
	"github.com/H-BF/corlib/pkg/atomic"
	"github.com/H-BF/corlib/pkg/patterns/observer"
	"github.com/pkg/errors"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

type (
	// SyncStatusError -
	SyncStatusError struct {
		error
		observer.EventType
	}

	// SyncStatusValue -
	SyncStatusValue struct {
		model.SyncStatus
		observer.EventType
	}
)

// SyncStatusEventSource -
type SyncStatusEventSource struct {
	Subject       observer.Subject
	SGClient      SGClient
	CheckInterval time.Duration
	UsePushModel  bool
}

// Run -
func (ss *SyncStatusEventSource) Run(ctx context.Context) error {
	if ss.CheckInterval < time.Second {
		panic("'SyncStatus/CheckInterval' is less than 1s")
	}
	log := logger.FromContext(ctx).Named("db-status-watcher")
	mode := "pull"
	if ss.UsePushModel {
		mode = "push"
	}
	log.Infow("start", "mode", mode)
	defer log.Info("stop")
	tc := time.NewTicker(ss.CheckInterval)
	defer tc.Stop()
	if ss.UsePushModel {
		return ss.push(ctx, tc, log)
	}
	return ss.pull(ctx, tc, log)
}

func (ss *SyncStatusEventSource) push(ctx context.Context, tc *time.Ticker, log logger.TypeOfLogger) (err error) {
	var (
		stream     sgAPI.SecGroupService_SyncStatusesClient
		resp       *sgAPI.SyncStatusResp
		syncStatus atomic.Value[model.SyncStatus]
		wg         sync.WaitGroup
		closeCh    = make(chan struct{})
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-closeCh:
				return
			case <-tc.C:
				syncStatus.Clear(func(t model.SyncStatus) {
					ss.Subject.Notify(SyncStatusValue{
						SyncStatus: t,
					})
				})
			}
		}
	}()
	defer func() {
		close(closeCh)
		if err != nil {
			log.Errorf("will exit cause %v", err)
			ss.Subject.Notify(SyncStatusError{error: err})
		}
		wg.Wait()
	}()
	if stream, err = ss.SGClient.SyncStatuses(ctx, new(emptypb.Empty)); err != nil {
		return err
	}
	log.Debug("connected")
	for {
		if resp, err = stream.Recv(); err != nil {
			return err
		}
		syncStatus.Store(model.SyncStatus{
			UpdatedAt: resp.GetUpdatedAt().AsTime(),
		}, nil)
	}
}

func (ss *SyncStatusEventSource) pull(ctx context.Context, tc *time.Ticker, log logger.TypeOfLogger) (err error) {
	defer func() {
		if err != nil {
			log.Errorf("will exit cause %v", err)
			ss.Subject.Notify(SyncStatusError{error: err})
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tc.C:
			st, e := ss.getSyncStatus(ctx)
			if e != nil {
				return e
			}
			if st != nil {
				ss.Subject.Notify(SyncStatusValue{SyncStatus: *st})
			}
		}
	}
}

func (ss *SyncStatusEventSource) getSyncStatus(ctx context.Context) (*model.SyncStatus, error) {
	var ret *model.SyncStatus
	resp, err := ss.SGClient.SyncStatus(ctx, new(emptypb.Empty))
	if err == nil {
		ret = new(model.SyncStatus)
		ret.UpdatedAt = resp.GetUpdatedAt().AsTime()
	} else if e := errors.Cause(err); status.Code(e) == codes.NotFound {
		err = nil
	}
	return ret, err
}

// Cause -
func (e SyncStatusError) Cause() error {
	return e.error
}
