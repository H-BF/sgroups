package agent

import (
	"context"
	"time"

	sgAPI "github.com/H-BF/sgroups/internal/api/sgroups"
	grpc_client "github.com/H-BF/sgroups/internal/grpc"

	config "github.com/H-BF/corlib/pkg/plain-config"

	"github.com/pkg/errors"
	"google.golang.org/grpc/credentials"
)

// SGClient is an alias to 'sgAPI.ClosableClient'
type SGClient = sgAPI.ClosableClient

// NewSGClient makes 'sgroups' API client
func NewSGClient(ctx context.Context) (ret *SGClient, err error) {
	const api = "NewSGClient"

	defer func() {
		err = errors.WithMessage(err, api)
	}()

	addr, err := SGroupsAddress.Value(ctx)
	if err != nil {
		return nil, err
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
		return nil, err
	}
	var creds credentials.TransportCredentials
	if creds, err = makeSgroupsClientCreds(ctx); err != nil {
		return nil, err
	}
	bld := grpc_client.ClientFromAddress(addr).
		WithDialDuration(dialDuration).
		WithCreds(creds).
		WithUserAgent(UserAgent.MustValue(ctx))
	if v, e := SGroupsUseJsonCodec.Value(ctx); e == nil && v {
		bld = bld.WithDefaultCodecByName(grpc_client.JsonCodecName)
	} else if e != nil && !errors.Is(e, config.ErrNotFound) {
		return nil, e
	}
	if o, e := SGroupsAPIpathPrefix.Value(ctx); e == nil {
		bld = bld.WithPathPrefix(o)
	} else if !errors.Is(e, config.ErrNotFound) {
		return nil, e
	}
	var c SGClient
	if c, err = sgAPI.NewClosableClient(ctx, bld); err != nil {
		return nil, err
	}
	return &c, err
}
