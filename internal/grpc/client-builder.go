package grpc

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path"
	"time"

	grpc_client "github.com/H-BF/corlib/client/grpc"
	"github.com/H-BF/corlib/pkg/backoff"
	netPkg "github.com/H-BF/corlib/pkg/net"
	"github.com/H-BF/sgroups/internal/patterns"

	grpc_retry "github.com/grpc-ecosystem/go-grpc-middleware/retry"
	"github.com/pkg/errors"
	"google.golang.org/grpc"
	grpcBackoff "google.golang.org/grpc/backoff"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/encoding"
)

// ClientFromAddress  builder for 'grpc' client conn
func ClientFromAddress(addr string) clientConnBuilder {
	return clientConnBuilder{addr: addr}
}

type (
	// Backoff is an alias to backoff.Backoff
	Backoff = backoff.Backoff

	// Codec is a type alias to grpc/encoding.Codec
	Codec = encoding.Codec

	// TransportCredentials is an alias to credentials.TransportCredentials
	TransportCredentials = credentials.TransportCredentials

	clientConnBuilder struct {
		addr           string
		dialDuration   time.Duration
		retriesBackoff Backoff
		maxRetries     uint
		creds          TransportCredentials
		userAgent      string
		defCallCodec   Codec
		pathPrefix     string
	}

	nonRootPathClientConn struct {
		ClientConn
		pathPrefix string
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

// WithUserAgent add user-agent into query metagata
func (bld clientConnBuilder) WithUserAgent(userAgent string) clientConnBuilder {
	bld.userAgent = userAgent
	return bld
}

// WithDefaultCodec set default call grpc codec
func (bld clientConnBuilder) WithDefaultCodec(codec Codec) clientConnBuilder {
	bld.defCallCodec = codec
	return bld
}

// WithDefaultCodecByName set default call grpc codec from its name
func (bld clientConnBuilder) WithDefaultCodecByName(codecName string) clientConnBuilder {
	c := encoding.GetCodec(codecName)
	if c == nil {
		panic(
			fmt.Errorf("grpc codec '%s' is not registered", codecName),
		)
	}
	bld.defCallCodec = c
	return bld
}

// WithPathPrefix -
func (bld clientConnBuilder) WithPathPrefix(p string) clientConnBuilder {
	bld.pathPrefix = p
	return bld
}

// WithCreds -
func (bld clientConnBuilder) WithCreds(creds credentials.TransportCredentials) clientConnBuilder {
	bld.creds = creds
	return bld
}

// NewConn makes new grpc client conn && ipml 'ClientConnProvider'
func (bld clientConnBuilder) New(ctx context.Context) (ClientConn, error) {
	const api = "grpc/new-client-conn"

	var (
		err                error
		endpoint           string
		c                  ClientConn
		streamInterceptors []grpc.StreamClientInterceptor
		unaryInterceptors  []grpc.UnaryClientInterceptor
	)

	if endpoint, err = bld.endpoint(); err != nil {
		return nil, errors.WithMessage(err, api)
	}
	creds := bld.creds
	if creds == nil {
		creds = insecure.NewCredentials()
	}
	dialOpts := []grpc.DialOption{
		grpc.WithTransportCredentials(creds),
	}
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
		streamInterceptors = append(streamInterceptors, grpc_retry.StreamClientInterceptor(retrOpts...))
		unaryInterceptors = append(unaryInterceptors, grpc_retry.UnaryClientInterceptor(retrOpts...))
	}
	hostname, err := os.Hostname()
	if err != nil {
		return nil, errors.WithMessage(err, api)
	}
	hostNameInterceptors := grpc_client.HostNamePropagator(hostname)
	dialOpts = append(dialOpts,
		grpc.WithUserAgent(bld.userAgent),
		grpc.WithChainStreamInterceptor(
			append(streamInterceptors, hostNameInterceptors.ClientStream())...),
		grpc.WithChainUnaryInterceptor(
			append(unaryInterceptors, hostNameInterceptors.ClientUnary())...),
	)
	if c := bld.defCallCodec; c != nil {
		dialOpts = append(dialOpts,
			grpc.WithDefaultCallOptions(grpc.ForceCodec(c)),
		)
	}
	if c, err = grpc.DialContext(ctx, endpoint, dialOpts...); err != nil {
		return nil, errors.WithMessage(err, api)
	}
	var p patterns.Path
	if err = p.Set(bld.pathPrefix); err != nil {
		_ = c.Close()
		return nil, errors.WithMessage(err, api)
	}
	if !p.IsEmpty() {
		c = &nonRootPathClientConn{
			ClientConn: c,
			pathPrefix: p.String(),
		}
	}
	return c, nil
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

// Invoke -
func (cc *nonRootPathClientConn) Invoke(ctx context.Context, method string, args any, reply any, opts ...grpc.CallOption) error {
	meth := cc.path(method)
	return cc.ClientConn.Invoke(ctx, meth, args, reply, opts...)
}

// NewStream -
func (cc *nonRootPathClientConn) NewStream(ctx context.Context, desc *grpc.StreamDesc, method string, opts ...grpc.CallOption) (grpc.ClientStream, error) {
	meth := cc.path(method)
	return cc.ClientConn.NewStream(ctx, desc, meth, opts...)
}

func (cc *nonRootPathClientConn) path(name string) string {
	return path.Join(cc.pathPrefix, name)
}
