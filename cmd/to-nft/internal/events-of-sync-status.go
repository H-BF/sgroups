package internal

import (
	"context"
	"time"

	model "github.com/H-BF/sgroups/internal/models/sgroups"

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
}

// Run -
func (ss *SyncStatusEventSource) Run(ctx context.Context) error {
	if ss.CheckInterval < time.Second {
		panic("'SyncStatus/CheckInterval' is less than 1s")
	}
	log := logger.FromContext(ctx).Named("sync-db-status")
	log.Info("start")
	defer log.Info("stop")
	tc := time.NewTicker(ss.CheckInterval)
	defer tc.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tc.C:
			st, e := GetSyncStatus(ctx, ss.SGClient)
			if e != nil {
				log.Error(e)
				ss.AgentSubj.Notify(SyncStatusError{error: e})
				//return e
				break
			}
			if st != nil {
				ss.AgentSubj.Notify(SyncStatusValue{SyncStatus: *st})
			}
		}
	}
}

// GetSyncStatus -
func GetSyncStatus(ctx context.Context, c SGClient) (*model.SyncStatus, error) {
	var ret *model.SyncStatus
	resp, err := c.SyncStatus(ctx, new(emptypb.Empty))
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
