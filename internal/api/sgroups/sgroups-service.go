package sgroups

import (
	"context"

	"github.com/H-BF/corlib/server"
	sgPkg "github.com/H-BF/protos/pkg"
	sg "github.com/H-BF/protos/pkg/api/sgroups"
	grpcRt "github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"
)

//NewSGroupsService creates service
func NewSGroupsService(ctx context.Context) server.APIService {
	return &sgService{
		appCtx: ctx,
	}
}

type sgService struct {
	appCtx context.Context

	sg.UnimplementedSecGroupServiceServer
}

var (
	_ sg.SecGroupServiceServer = (*sgService)(nil)
	_ server.APIService        = (*sgService)(nil)
	_ server.APIGatewayProxy   = (*sgService)(nil)

	//SecGroupSwaggerUtil ...
	SecGroupSwaggerUtil sgPkg.SwaggerUtil[sg.SecGroupServiceServer]
)

//Description impl server.APIService
func (srv *sgService) Description() grpc.ServiceDesc {
	return sg.SecGroupService_ServiceDesc
}

//RegisterGRPC impl server.APIService
func (srv *sgService) RegisterGRPC(_ context.Context, s *grpc.Server) error {
	sg.RegisterSecGroupServiceServer(s, srv)
	return nil
}

//RegisterProxyGW impl server.APIGatewayProxy
func (srv *sgService) RegisterProxyGW(ctx context.Context, mux *grpcRt.ServeMux, c *grpc.ClientConn) error {
	return sg.RegisterSecGroupServiceHandler(ctx, mux, c)
}
