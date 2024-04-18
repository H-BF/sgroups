package sgroups

import (
	"context"
	"fmt"
	"net/url"
	"path"

	"github.com/H-BF/sgroups/internal/patterns"
	registry "github.com/H-BF/sgroups/internal/registry/sgroups"

	"github.com/H-BF/corlib/server"
	sgPkg "github.com/H-BF/protos/pkg"
	sg "github.com/H-BF/protos/pkg/api/sgroups"
	grpcRt "github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/pkg/errors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// SGroupsServiceOpt -
type SGroupsServiceOpt interface {
	apply(*sgService)
}

// NewSGroupsService creates service
func NewSGroupsService(ctx context.Context, r registry.Registry, opts ...SGroupsServiceOpt) server.APIService {
	ret := &sgService{
		appCtx: ctx,
		reg:    r,
	}
	for _, o := range opts {
		o.apply(ret)
	}
	return ret
}

// WithAPIpathPrefixes -
func WithAPIpathPrefixes(pp ...string) SGroupsServiceOpt {
	return sgSrvFuncOpt(func(ss *sgService) {
		ss.pathPrefixes = append(ss.pathPrefixes, pp...)
	})
}

type sgSrvFuncOpt func(*sgService)

type sgService struct {
	sg.UnimplementedSecGroupServiceServer
	appCtx       context.Context
	reg          registry.Registry
	pathPrefixes []string
}

var (
	_ sg.SecGroupServiceServer = (*sgService)(nil)
	_ server.APIService        = (*sgService)(nil)
	_ server.APIGatewayProxy   = (*sgService)(nil)

	//SecGroupSwaggerUtil ...
	SecGroupSwaggerUtil sgPkg.SwaggerUtil[sg.SecGroupServiceServer]

	errServiceIsClosing = status.Error(codes.Unavailable,
		"'sgroups' service is about to be closed")
)

// Description impl server.APIService
func (srv *sgService) Description() grpc.ServiceDesc {
	return sg.SecGroupService_ServiceDesc
}

// RegisterGRPC impl server.APIService
func (srv *sgService) RegisterGRPC(_ context.Context, s *grpc.Server) error {
	desc := srv.Description()
	s.RegisterService(&desc, srv)
	if len(srv.pathPrefixes) > 0 {
		flt := map[string]struct{}{}
		var p patterns.Path
		for _, pt := range srv.pathPrefixes {
			if e := p.Set(pt); e != nil {
				return fmt.Errorf("SgService: register GRPC API with additional path prefix: %v", e)
			}
			if !p.IsEmpty() {
				ss := p.String()
				if _, seen := flt[ss]; !seen {
					flt[ss] = struct{}{}
					desc1 := desc
					desc1.ServiceName = path.Join(ss, desc.ServiceName)
					s.RegisterService(&desc1, srv)
				}
			}
		}
	}
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

func (f sgSrvFuncOpt) apply(srv *sgService) {
	f(srv)
}
