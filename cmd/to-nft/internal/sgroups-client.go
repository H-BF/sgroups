package internal

import (
	"context"
	"time"

	client "github.com/H-BF/corlib/client/grpc"
	netPkg "github.com/H-BF/corlib/pkg/net"
	sg "github.com/H-BF/protos/pkg/api/sgroups"
	"github.com/H-BF/sgroups/internal/config"
	"github.com/pkg/errors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/credentials/insecure"
)

// SGClient SecGrpups server client
type SGClient interface {
	sg.SecGroupServiceClient
	client.Closable
}

// NewSGClient creates SGClient
func NewSGClient(ctx context.Context) (SGClient, error) {
	const api = "New-SG-Client"

	addr, err := SGroupsAddress.Value(ctx)
	if err != nil {
		return nil, errors.WithMessage(err, api)
	}
	var ep *netPkg.Endpoint
	if ep, err = netPkg.ParseEndpoint(addr); err != nil {
		return nil, errors.WithMessage(err, api)
	}
	if ep.IsUnixDomain() {
		addr = ep.FQN()
	} else {
		addr, _ = ep.Address()
	}

	var dialDuration time.Duration
	dialDuration, err = SGroupsDialDuration.Value(ctx)
	if errors.Is(err, config.ErrNotFound) {
		dialDuration, err = ServicesDefDialDuration.Value(ctx)
		if errors.Is(err, config.ErrNotFound) {
			err = nil
		}
	}
	if err != nil {
		return nil, errors.WithMessage(err, api)
	}
	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	}
	if dialDuration != 0 {
		if dialDuration < time.Second {
			dialDuration = time.Second
		}
		bkCfg := backoff.DefaultConfig
		bkCfg.BaseDelay = dialDuration / 10
		bkCfg.Multiplier = 1.01
		bkCfg.Jitter = 0.1
		bkCfg.MaxDelay = dialDuration
		opts = append(opts, grpc.WithConnectParams(grpc.ConnectParams{
			Backoff:           bkCfg,
			MinConnectTimeout: dialDuration / 10,
		}))
	} else {
		opts = append(opts, grpc.WithReturnConnectionError())
	}
	var c grpc.ClientConnInterface
	if c, err = grpc.DialContext(ctx, addr, opts...); err != nil {
		return nil, errors.WithMessage(err, api)
	}
	c = client.WithErrorWrapper(c, "SG")
	closable := client.MakeCloseable(c)
	return struct {
		sg.SecGroupServiceClient
		client.Closable
	}{
		sg.NewSecGroupServiceClient(closable),
		closable,
	}, nil
}
