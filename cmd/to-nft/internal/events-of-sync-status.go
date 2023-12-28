package internal

import (
	"context"
	"time"

	sgAPI "github.com/H-BF/protos/pkg/api/sgroups"
	model "github.com/H-BF/sgroups/internal/models/sgroups"
	"github.com/H-BF/sgroups/pkg/atomic"

	"github.com/H-BF/corlib/logger"
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
	AgentSubj     observer.Subject
	SGClient      SGClient
	CheckInterval time.Duration
	UsePushModel  bool
}

// Run -
func (ss *SyncStatusEventSource) Run(ctx context.Context) error {
	if ss.CheckInterval < time.Second {
		panic("'SyncStatus/CheckInterval' is less than 1s")
	}
	log := logger.FromContext(ctx).Named("sync-db-status")
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

func (ss *SyncStatusEventSource) push(ctx context.Context, tc *time.Ticker, log logger.TypeOfLogger) error {
	var syncStatus atomic.Value[model.SyncStatus]
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-tc.C:
				syncStatus.Clear(func(t model.SyncStatus) {
					ss.AgentSubj.Notify(SyncStatusValue{
						SyncStatus: t,
					})
				})
			}
		}
	}()

	const reconnectTimeut = 10 * time.Second
	var (
		stream sgAPI.SecGroupService_SyncStatusesClient
		err    error
		resp   *sgAPI.SyncStatusResp
	)
	HcSyncStatus.Set(true)
loop:
	for req := new(emptypb.Empty); ; {
		if err != nil {
			HcSyncStatus.Set(false)
			stream = nil
			if e := errors.Cause(err); status.Code(e) != codes.Canceled {
				log.Error(err, "; it will reconnect after ", reconnectTimeut)
				ss.AgentSubj.Notify(SyncStatusError{error: err})
			}
			select {
			case <-ctx.Done():
				err = ctx.Err()
				break loop
			case <-time.After(reconnectTimeut):
			}
		}
		if stream == nil {
			stream, err = ss.SGClient.SyncStatuses(ctx, req)
			if err == nil {
				log.Debug("connected")
			}
		}
		if err == nil {
			resp, err = stream.Recv()
		}
		if err == nil {
			HcSyncStatus.Set(true)
			syncStatus.Store(model.SyncStatus{
				UpdatedAt: resp.GetUpdatedAt().AsTime(),
			}, nil)
		}
	}
	return err
}

func (ss *SyncStatusEventSource) pull(ctx context.Context, tc *time.Ticker, log logger.TypeOfLogger) error {
	HcSyncStatus.Set(true)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tc.C:
			st, e := ss.getSyncStatus(ctx)
			if e == nil && st != nil {
				HcSyncStatus.Set(true)
				ss.AgentSubj.Notify(SyncStatusValue{SyncStatus: *st})
			}
			if e = errors.Cause(e); e != nil && status.Code(e) != codes.Canceled {
				HcSyncStatus.Set(false)
				log.Error(e)
				ss.AgentSubj.Notify(SyncStatusError{error: e})
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
