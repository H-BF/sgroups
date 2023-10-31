package provider

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"path"
	"strings"
	"time"

	sgAPI "github.com/H-BF/sgroups/internal/api/sgroups"
	client "github.com/H-BF/sgroups/internal/grpc-client"
	registry "github.com/H-BF/sgroups/internal/registry/sgroups"
	"google.golang.org/grpc"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/stretchr/testify/suite"
)

type (
	baseResourceTests struct {
		suite.Suite

		ctx               context.Context
		ctxCancel         func()
		server            *embedServer
		sgClient          sgAPI.ClosableClient
		providerConfig    string
		providerFactories map[string]func() (tfprotov6.ProviderServer, error)
	}

	embedServer struct {
		Addr       string
		socketPath string
		grpcServer *grpc.Server
	}
)

func (sui *baseResourceTests) SetupSuite() {
	sui.ctx = context.Background()
	if dl, ok := sui.T().Deadline(); ok {
		sui.ctx, sui.ctxCancel = context.WithDeadline(sui.ctx, dl)
	}

	sui.server = NewServer()
	sui.Require().NoError(sui.server.RunDetached(sui.ctx), "run embed server failed")

	sui.providerConfig = `
		provider "sgroups" {
			address = ` + sui.server.Addr + `
		}
		`
	dialDuration := lookupEnvWithDefault("SGROUPS_DIAL_DURATION", "10s")
	connDuration, err := time.ParseDuration(dialDuration)
	sui.Require().Nil(err)

	builder := client.FromAddress(sui.server.Addr).
		WithDialDuration(connDuration)

	sui.sgClient, err = sgAPI.NewClosableClient(sui.ctx, builder)
	sui.Require().NoError(err)

	sui.providerFactories = map[string]func() (tfprotov6.ProviderServer, error){
		"sgroups": providerserver.NewProtocol6WithError(Factory("test")()),
	}
}

func (sui *baseResourceTests) TearDownSuite() {
	err := sui.sgClient.CloseConn()
	sui.Require().NoError(err)

	sui.server.Stop()

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
	server.socketPath = path.Join("/tmp", fmt.Sprintf("test-%v-%v.socket", os.Getpid(), time.Now().Nanosecond()))
	server.Addr = fmt.Sprintf("unix://%s", server.socketPath)
	return server
}

/*//TODO:
Итак - Иван опять наговнокодил-наизобретал )))))
- минус в карму
Так
    еще раз
	- ноем сокрушаемся матюгаемся сыплем проклятья заламываем
	  руки в мольбах к небу
	- изучаем корлиб с кактусом в прикуску
	- изучаем как сделано в cmd/sgrpups/main.go
	- делаем похожим способом
	- пишем восхитительный код
*/

func (server *embedServer) RunDetached(ctx context.Context) error {
	lis, err := net.Listen("unix", server.socketPath)
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

	var opts []grpc.ServerOption
	server.grpcServer = grpc.NewServer(opts...)
	if err := service.RegisterGRPC(ctx, server.grpcServer); err != nil {
		return err
	}

	go func() {
		if err := server.grpcServer.Serve(lis); err != nil {
			fmt.Println("server stopped due" + err.Error())
		}
	}()
	os.Setenv("SGROUPS_ADDRESS", server.Addr)
	fmt.Printf("server started on %s\n", server.socketPath)
	return nil
}

func (server *embedServer) Stop() {
	server.grpcServer.Stop()
}
