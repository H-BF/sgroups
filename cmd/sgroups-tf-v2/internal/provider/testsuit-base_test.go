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
	registry "github.com/H-BF/sgroups/internal/registry/sgroups"

	pkgNet "github.com/H-BF/corlib/pkg/net"
	corlib "github.com/H-BF/corlib/server"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/stretchr/testify/suite"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	serverAddrEnv = "SGROUPS_ADDRESS"
)

type (
	baseResourceTests struct {
		suite.Suite

		ctx               context.Context
		ctxCancel         func()
		server            *backendServerAPI
		closeClient       func() error
		sgClient          sgAPI.Client
		providerConfig    string
		providerFactories map[string]func() (tfprotov6.ProviderServer, error)
	}

	backendServerAPI struct {
		corlib.APIService
		Addr     string
		eventsCh chan interface{}
	}
)

func (sui *baseResourceTests) SetupSuite() {
	sui.ctx = context.Background()
	if dl, ok := sui.T().Deadline(); ok {
		sui.ctx, sui.ctxCancel = context.WithDeadline(sui.ctx, dl)
	}

	sui.server = NewServer()
	err := sui.server.runBackendServer(sui.ctx)
	sui.Require().NoErrorf(err, "run embed server failed: %s", err)

	sui.providerConfig = `
		provider "sgroups" {
			address = ` + sui.server.Addr + `
		}
		`

	con, err := grpc.DialContext(sui.ctx, sui.server.Addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()))

	sui.closeClient = func() error {
		return con.Close()
	}
	sui.sgClient = sgAPI.NewClient(con)
	sui.Require().NoError(err)

	sui.providerFactories = map[string]func() (tfprotov6.ProviderServer, error){
		"sgroups": providerserver.NewProtocol6WithError(Factory("test")()),
	}
}

func (sui *baseResourceTests) TearDownSuite() {
	sui.NoError(sui.closeClient())

	if sui.ctxCancel != nil {
		sui.ctxCancel()
	}
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

func NewServer() *backendServerAPI {
	server := new(backendServerAPI)
	socketPath := path.Join("/tmp", fmt.Sprintf("tf-provider-test-%v-%v.socket", os.Getpid(), time.Now().Nanosecond()))
	server.Addr = fmt.Sprintf("unix://%s", socketPath)
	server.eventsCh = make(chan interface{})
	return server
}

// OnStart implements APIServiceOnStartEvent
func (server *backendServerAPI) OnStart() {
	if server.eventsCh == nil {
		panic("eventsCh is nil")
	}
	server.eventsCh <- "started"
}

func (server *backendServerAPI) runBackendServer(ctx context.Context) error {
	endpoint, err := pkgNet.ParseEndpoint(server.Addr)
	if err != nil {
		return err
	}

	m, err := registry.NewMemDB(registry.TblSecGroups,
		registry.TblSecRules, registry.TblNetworks,
		registry.TblSyncStatus, registry.TblFqdnRules,
		registry.IntegrityChecker4SG(),
		registry.IntegrityChecker4SGRules(),
		registry.IntegrityChecker4FqdnRules(),
		registry.IntegrityChecker4Networks())
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

	go func() {
		if err := apiServer.Run(ctx, endpoint); err != nil {
			server.eventsCh <- err
		}
	}()

	ev := <-server.eventsCh
	if err, ok := ev.(error); ok {
		return err
	}

	os.Setenv(serverAddrEnv, server.Addr)
	return nil
}

func TestEmpty(_ *testing.T) {}
