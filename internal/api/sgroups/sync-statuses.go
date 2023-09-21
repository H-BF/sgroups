package sgroups

import (
	"github.com/H-BF/corlib/logger"
	"github.com/H-BF/sgroups/internal/models/sgroups"
	registry "github.com/H-BF/sgroups/internal/registry/sgroups"
	"time"

	sg "github.com/H-BF/protos/pkg/api/sgroups"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var (
	updatePeriod = 3 * time.Second
	nextSubId    int32
)

type sub struct {
	stream   sg.SecGroupService_SyncStatusesServer // stream is the server side of the RPC stream
	finished chan<- bool                           // finished is used to signal closure of a client subscribing goroutine
}

// SyncStatuses impl sgService
func (srv *sgService) SyncStatuses(_ *emptypb.Empty, stream sg.SecGroupService_SyncStatusesServer) (err error) {
	defer func() {
		err = correctError(err)
	}()
	var reader registry.Reader
	ctx := stream.Context()
	if reader, err = srv.registryReader(ctx); err != nil {
		return err
	}
	defer reader.Close() //lint:nolint
	var st *sgroups.SyncStatus
	st, err = reader.GetSyncStatus(ctx)
	if err != nil {
		return err
	}
	if st != nil {
		if err = stream.Send(&sg.SyncStatusResp{
			UpdatedAt: timestamppb.New(st.UpdatedAt),
		}); err != nil {
			return err
		}
	}

	fin := make(chan bool)
	reqId := reqId()
	srv.statusSubscribers.Store(reqId, sub{
		stream:   stream,
		finished: fin,
	})

	// Keep this scope alive because once this scope exits - the stream is closed
	for {
		select {
		case <-fin:
			logger.Infof(ctx, "Got finish signal for client: %d", reqId)
			return nil
		case <-stream.Context().Done():
			logger.Infof(ctx, "Client ID %d was disconnected", reqId)
			return nil
		}
	}
}

func reqId() int32 {
	nextSubId++
	return nextSubId
}

func (srv *sgService) statusUpdater() {
	logger.Info(srv.appCtx, "Status Updater started")
	var (
		err    error
		reader registry.Reader
	)
	if reader, err = srv.registryReader(srv.appCtx); err != nil {
		logger.Error(srv.appCtx, "Cant get registry reader")
		return
	}
	defer reader.Close() //lint:nolint
	ticker := time.NewTicker(updatePeriod)

loop:
	for {
		select {
		case <-srv.appCtx.Done():
			logger.Info(srv.appCtx, "Status Updater goes down")
			break loop
		case <-ticker.C:
			var st *sgroups.SyncStatus
			st, err = reader.GetSyncStatus(srv.appCtx)
			if err == nil {
				var resp sg.SyncStatusResp
				if st == nil {
					resp.UpdatedAt = timestamppb.New(time.Time{}) // zero time to make it earlier than next updates
				} else {
					resp.UpdatedAt = timestamppb.New(st.UpdatedAt)
				}

				var unsubscribe []int32
				srv.statusSubscribers.Range(func(k, v interface{}) bool {
					id, ok := k.(int32)
					if !ok {
						logger.Errorf(srv.appCtx, "Failed to cast subscriber key: %T", k)
						return false
					}
					sub, ok := v.(sub)
					if !ok {
						logger.Errorf(srv.appCtx, "Failed to cast subscriber value: %T", v)
						return false
					}
					if err = sub.stream.Send(&resp); err != nil {
						logger.Errorf(srv.appCtx, "Failed to send data to client: %v", err)
						select {
						case sub.finished <- true:
							logger.Errorf(srv.appCtx, "Unsubscribe client: %d", id)
						default:
							// Default case is to avoid blocking in case client has already unsubscribed
						}
						unsubscribe = append(unsubscribe, id)
					}
					return true
				})

				for _, id := range unsubscribe {
					srv.statusSubscribers.Delete(id)
				}
			}
		}

	}
}
