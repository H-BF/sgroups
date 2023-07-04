package grpc_client

import (
	"context"
	"net/url"
	"time"

	"github.com/H-BF/corlib/pkg/backoff"
	netPkg "github.com/H-BF/corlib/pkg/net"
	grpc_retry "github.com/grpc-ecosystem/go-grpc-middleware/retry"
	"github.com/pkg/errors"
	"google.golang.org/grpc"
	grpcBackoff "google.golang.org/grpc/backoff"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

// FromAddress  builder for 'grpc' client conn
func FromAddress(addr string) clientConnBuilder {
	return clientConnBuilder{addr: addr}
}

type (
	// Backoff is an alias to backoff.Backoff
	Backoff = backoff.Backoff

	// TransportCredentials is an alias to credentials.TransportCredentials
	TransportCredentials = credentials.TransportCredentials

	clientConnBuilder struct {
		addr           string
		dialDuration   time.Duration
		retriesBackoff Backoff
		maxRetries     uint
		creds          TransportCredentials
	}
)

var _ ConnProvider = (*clientConnBuilder)(nil)

// WithDialDuration add max dial dutarion
func (bld clientConnBuilder) WithDialDuration(d time.Duration) clientConnBuilder {
	bld.dialDuration = d
	return bld
}

// WithMaxRetries adds max retries when call method
func (bld clientConnBuilder) WithMaxRetries(r uint) clientConnBuilder {
	bld.maxRetries = r
	return bld
}

// WithRetriesBackoff adds backoff for call retries
func (bld clientConnBuilder) WithRetriesBackoff(b backoff.Backoff) clientConnBuilder {
	_ = (*grpc.ClientConn)(nil)
	bld.retriesBackoff = b
	return bld
}

// NewConn makes new grpc client conn && ipml 'ClientConnProvider'
func (bld clientConnBuilder) New(ctx context.Context) (*grpc.ClientConn, error) {
	const api = "grpc/new-client-conn"

	var (
		err      error
		endpoint string
		dialOpts []grpc.DialOption
		c        *grpc.ClientConn
	)

	if endpoint, err = bld.endpoint(); err != nil {
		return nil, errors.WithMessage(err, api)
	}
	if bld.creds == nil {
		bld.creds = insecure.NewCredentials()
	}
	dialOpts = append(dialOpts, grpc.WithTransportCredentials(bld.creds))
	if dialDuration := bld.dialDuration; dialDuration <= 0 {
		dialOpts = append(dialOpts, grpc.WithReturnConnectionError())
	} else {
		if dialDuration < time.Second {
			dialDuration = time.Second
		}
		bkCfg := grpcBackoff.DefaultConfig
		bkCfg.BaseDelay = dialDuration / 10
		bkCfg.Multiplier = 1.01
		bkCfg.Jitter = 0.1
		bkCfg.MaxDelay = dialDuration
		dialOpts = append(dialOpts, grpc.WithConnectParams(grpc.ConnectParams{
			Backoff:           bkCfg,
			MinConnectTimeout: dialDuration / 10,
		}))
	}
	if maxRetries := bld.maxRetries; maxRetries > 0 {
		retrOpts := []grpc_retry.CallOption{grpc_retry.WithMax(maxRetries)}
		if bk := bld.retriesBackoff; bk != nil {
			bld.retriesBackoff.Reset()
			periods := make(map[uint]time.Duration)
			for i := uint(0); i < maxRetries; i++ {
				nextBackoff := bk.NextBackOff()
				if nextBackoff <= 0 {
					break
				}
				periods[i+1] = nextBackoff
			}
			retrOpts = append(retrOpts,
				grpc_retry.WithBackoff(func(attempt uint) time.Duration {
					return periods[attempt]
				}),
			)
		}
		retrOpts = append(retrOpts, grpc_retry.WithCodes(codes.Unavailable))
		dialOpts = append(dialOpts,
			grpc.WithStreamInterceptor(grpc_retry.StreamClientInterceptor(retrOpts...)),
			grpc.WithUnaryInterceptor(grpc_retry.UnaryClientInterceptor(retrOpts...)),
		)
	}
	c, err = grpc.DialContext(ctx, endpoint, dialOpts...)
	return c, errors.WithMessage(err, api)
}

func (bld *clientConnBuilder) endpoint() (string, error) {
	ep, err := netPkg.ParseEndpoint(bld.addr)
	if err == nil {
		if ep.IsUnixDomain() {
			return ep.FQN(), nil
		}
		var ret string
		if ret, err = ep.Address(); err == nil {
			return ret, nil
		}
	}
	if _, err = url.Parse(bld.addr); err == nil {
		return bld.addr, nil
	}
	return "", errors.WithMessagef(err, "bad address (%s)", bld.addr)
}
