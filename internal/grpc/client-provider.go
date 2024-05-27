package grpc

import (
	"context"

	inner "github.com/H-BF/corlib/client/grpc"
)

// ClientConn is a type alias
type ClientConn = inner.ClientConn

// ConnProvider grpc client conn provider
type ConnProvider interface {
	New(ctx context.Context) (ClientConn, error)
}
