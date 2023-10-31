package provider

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path"
	"strings"
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

type (
	baseResourceTests struct {
		suite.Suite

		ctx               context.Context
		ctxCancel         func()
		server            *embedServer
		closeClient       func() error
		sgClient          sgAPI.Client
		providerConfig    string
		providerFactories map[string]func() (tfprotov6.ProviderServer, error)
	}

	embedServer struct {
		Addr string
	}
)

func (sui *baseResourceTests) SetupSuite() {
	sui.ctx = context.Background()
	if dl, ok := sui.T().Deadline(); ok {
		sui.ctx, sui.ctxCancel = context.WithDeadline(sui.ctx, dl)
	}

	sui.server = NewServer()
	err := sui.server.RunDetached(sui.ctx)
	sui.Require().NoErrorf(err, "run embed server failed: %s", err)

	sui.providerConfig = `
		provider "sgroups" {
			address = ` + sui.server.Addr + `
		}
		`

	con, err := grpc.DialContext(sui.ctx, sui.server.Addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock())

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

func NewServer() *embedServer {
	server := new(embedServer)
	socketPath := path.Join("/tmp", fmt.Sprintf("test-%v-%v.socket", os.Getpid(), time.Now().Nanosecond()))
	server.Addr = fmt.Sprintf("unix://%s", socketPath)
	return server
}

func (server *embedServer) RunDetached(ctx context.Context) error {
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
	service := sgAPI.NewSGroupsService(ctx, registry.NewRegistryFromMemDB(m))

	opts := []corlib.APIServerOption{
		corlib.WithServices(service),
	}

	apiServer, err := corlib.NewAPIServer(opts...)
	if err != nil {
		return err
	}

	go func() {
		if err := apiServer.Run(ctx, endpoint); err != nil {
			fmt.Println("server stopped due" + err.Error())
		}
	}()
	os.Setenv("SGROUPS_ADDRESS", server.Addr)
	fmt.Printf("server started on %s\n", server.Addr)
	return nil
}
