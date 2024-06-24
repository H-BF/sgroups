package sgroups

import (
	"context"
	pkgNet "github.com/H-BF/corlib/pkg/net"
	corlib "github.com/H-BF/corlib/server"
	registry "github.com/H-BF/sgroups/internal/registry/sgroups"
)

type BackendServerAPI struct {
	corlib.APIService
	started chan struct{}
}

func NewBackendServerAPI() *BackendServerAPI {
	return &BackendServerAPI{
		started: make(chan struct{}),
	}
}

// OnStart implements APIServiceOnStartEvent
func (server *BackendServerAPI) OnStart() {
	close(server.started)
}

func (server *BackendServerAPI) Run(ctx context.Context, addr string) error {
	endpoint, err := pkgNet.ParseEndpoint(addr)
	if err != nil {
		return err
	}

	m, err := registry.NewMemDB(registry.AllTables())
	if err != nil {
		return err
	}
	server.APIService = NewSGroupsService(ctx, registry.NewRegistryFromMemDB(m))

	opts := []corlib.APIServerOption{
		corlib.WithServices(server),
	}

	apiServer, err := corlib.NewAPIServer(opts...)
	if err != nil {
		return err
	}

	chRunFailure := make(chan error, 1)
	go func() {
		defer close(chRunFailure)
		if err := apiServer.Run(ctx, endpoint); err != nil {
			chRunFailure <- err
		}
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case e := <-chRunFailure:
		return e
	case <-server.started:
	}
	return nil
}
