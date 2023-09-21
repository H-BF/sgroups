package sgroups

import (
	"context"
	registry "github.com/H-BF/sgroups/internal/registry/sgroups"
	"net/url"
	"sync"

	"github.com/H-BF/corlib/server"
	sgPkg "github.com/H-BF/protos/pkg"
	sg "github.com/H-BF/protos/pkg/api/sgroups"
	grpcRt "github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/pkg/errors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// NewSGroupsService creates service
func NewSGroupsService(ctx context.Context, r registry.Registry) server.APIService {
	service := sgService{
		appCtx: ctx,
		reg:    r,
	}
	go service.statusUpdater()
	return &service
}

type sgService struct {
	appCtx            context.Context
	reg               registry.Registry
	statusSubscribers sync.Map

	sg.UnimplementedSecGroupServiceServer
}

var (
	_ sg.SecGroupServiceServer = (*sgService)(nil)
	_ server.APIService        = (*sgService)(nil)
	_ server.APIGatewayProxy   = (*sgService)(nil)

	//SecGroupSwaggerUtil ...
	SecGroupSwaggerUtil sgPkg.SwaggerUtil[sg.SecGroupServiceServer]

	errSuccess = errors.New("success")
)

// Description impl server.APIService
func (srv *sgService) Description() grpc.ServiceDesc {
	return sg.SecGroupService_ServiceDesc
}

// RegisterGRPC impl server.APIService
func (srv *sgService) RegisterGRPC(_ context.Context, s *grpc.Server) error {
	sg.RegisterSecGroupServiceServer(s, srv)
	return nil
}

// RegisterProxyGW impl server.APIGatewayProxy
func (srv *sgService) RegisterProxyGW(ctx context.Context, mux *grpcRt.ServeMux, c *grpc.ClientConn) error {
	return sg.RegisterSecGroupServiceHandler(ctx, mux, c)
}

func (srv *sgService) registryReader(ctx context.Context) (registry.Reader, error) {
	return srv.reg.Reader(ctx)
}

func (srv *sgService) registryWriter(ctx context.Context) (registry.Writer, error) {
	return srv.reg.Writer(ctx)
}

func correctError(err error) error {
	if err != nil && status.Code(err) == codes.Unknown {
		switch errors.Cause(err) {
		case context.DeadlineExceeded:
			return status.New(codes.DeadlineExceeded, err.Error()).Err()
		case context.Canceled:
			return status.New(codes.Canceled, err.Error()).Err()
		default:
			if e := new(url.Error); errors.As(err, &e) {
				switch errors.Cause(e.Err) {
				case context.Canceled:
					return status.New(codes.Canceled, err.Error()).Err()
				case context.DeadlineExceeded:
					return status.New(codes.DeadlineExceeded, err.Error()).Err()
				default:
					if e.Timeout() {
						return status.New(codes.DeadlineExceeded, err.Error()).Err()
					}
				}
			}
			err = status.New(codes.Internal, err.Error()).Err()
		}
	}
	return err
}
