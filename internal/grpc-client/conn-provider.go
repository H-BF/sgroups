package grpc_client

import (
	"context"

	"google.golang.org/grpc"
)

// ConnProvider grpc client conn provider
type ConnProvider interface {
	New(ctx context.Context) (*grpc.ClientConn, error)
}
