package grpc

import (
	"context"

	"google.golang.org/grpc"
)

// ClientConn - grpc client connection
type ClientConn interface {
	grpc.ClientConnInterface
	Close() error
}

// ConnProvider grpc client conn provider
type ConnProvider interface {
	New(ctx context.Context) (ClientConn, error)
}
