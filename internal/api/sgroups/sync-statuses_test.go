package sgroups

import (
	"context"

	api "github.com/H-BF/protos/pkg/api/sgroups"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
)

func (sui *sGroupServiceTests) Test_SyncStatuses() {
	stream := makeSyncStatusesStream()
	chE := make(chan error, 1)
	go func() {
		chE <- sui.srv.SyncStatuses(&emptypb.Empty{}, stream)
	}()

	makeUpdate := func(networkName string) {
		nw1 := sui.newNetwork(networkName, "10.10.10.0/24")
		sui.syncNetworks([]*api.Network{nw1}, api.SyncReq_FullSync)
	}

	var resp1, resp2 *api.SyncStatusResp

	makeUpdate("net1")
	resp1 = <-stream.out
	sui.Require().NotNil(resp1)

	makeUpdate("net2")
	resp2 = <-stream.out
	sui.Require().NotNil(resp2)

	stream.Cancel()

	sui.Require().Less(resp1.UpdatedAt.AsTime(), resp2.UpdatedAt.AsTime())
	err := <-chE
	sui.Require().NoError(err)
}

type syncStatusesStream struct {
	grpc.ServerStream
	ctx    context.Context
	out    chan *api.SyncStatusResp
	cancel context.CancelFunc
}

func makeSyncStatusesStream() *syncStatusesStream {
	ctx, cancel := context.WithCancel(context.Background())
	return &syncStatusesStream{
		out:    make(chan *api.SyncStatusResp),
		ctx:    ctx,
		cancel: cancel,
	}
}

func (s *syncStatusesStream) Context() context.Context {
	return s.ctx
}

func (s *syncStatusesStream) Send(resp *api.SyncStatusResp) error {
	select {
	case s.out <- resp:
		return nil
	case <-s.ctx.Done():
		return s.ctx.Err()
	}
}

func (s *syncStatusesStream) Cancel() {
	s.cancel()
}
