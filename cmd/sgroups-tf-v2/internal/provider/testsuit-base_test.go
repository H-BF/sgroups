package provider

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path"
	"strings"
	"testing"
	"time"

	sgAPI "github.com/H-BF/sgroups/internal/api/sgroups"
	g "github.com/H-BF/sgroups/internal/grpc"
	registry "github.com/H-BF/sgroups/internal/registry/sgroups"

	pkgNet "github.com/H-BF/corlib/pkg/net"
	corlib "github.com/H-BF/corlib/server"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/stretchr/testify/suite"
)

type (
	baseResourceTests struct {
		suite.Suite

		ctx               context.Context
		ctxCancel         func()
		servAddr          string
		sgClient          sgAPI.Client
		providerConfig    string
		providerFactories map[string]func() (tfprotov6.ProviderServer, error)
	}

	backendServerAPI struct {
		corlib.APIService
		started chan struct{}
	}
)

func (sui *baseResourceTests) SetupSuite() {
	sui.ctx = context.Background()
	if dl, ok := sui.T().Deadline(); ok {
		sui.ctx, sui.ctxCancel = context.WithDeadline(sui.ctx, dl)
	}
	sui.runBackendServer()

	sui.providerConfig = `
provider "sgroups" {
	address = ` + fmt.Sprintf("%q", sui.servAddr) + `
	dial_duration = "15s"
	use_json_codec = true
}
`
	con, err := g.ClientFromAddress(sui.servAddr).New(sui.ctx)
	sui.Require().NoError(err)
	sui.sgClient = sgAPI.NewClient(con)

	os.Setenv("TF_ACC", "1")
	sui.providerFactories = map[string]func() (tfprotov6.ProviderServer, error){
		"sgroups": providerserver.NewProtocol6WithError(Factory("test")()),
	}
}

func (sui *baseResourceTests) TearDownSuite() {
	if sui.ctxCancel != nil {
		sui.ctxCancel()
	}
}

func (sui *baseResourceTests) runBackendServer() {
	socketPath := path.Join("/tmp", fmt.Sprintf("tf-provider-test-%v-%v.socket", os.Getpid(), time.Now().Nanosecond()))
	sui.servAddr = fmt.Sprintf("unix://%s", socketPath)

	server := backendServerAPI{
		started: make(chan struct{}),
	}
	e := server.run(sui.ctx, sui.servAddr)
	sui.Require().NoError(e)
}

func slice2string[T fmt.Stringer](args ...T) string {
	data := bytes.NewBuffer(nil)
	for i, o := range args {
		if i > 0 {
			_, _ = data.WriteString(";  ")
		}
		_, _ = fmt.Fprintf(data, "%s", o)
	}
	return strings.ReplaceAll(data.String(), `"`, "'")
}

// OnStart implements APIServiceOnStartEvent
func (server *backendServerAPI) OnStart() {
	close(server.started)
}

func (server *backendServerAPI) run(ctx context.Context, addr string) error {
	endpoint, err := pkgNet.ParseEndpoint(addr)
	if err != nil {
		return err
	}

	m, err := registry.NewMemDB(registry.AllTables())
	if err != nil {
		return err
	}
	server.APIService = sgAPI.NewSGroupsService(ctx, registry.NewRegistryFromMemDB(m))

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

func TestEmpty(_ *testing.T) {}
