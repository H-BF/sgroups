package sgroups

import (
	"context"
	"net"
	"net/url"
	"strings"

	"github.com/H-BF/protos/pkg/api/common"
	sg "github.com/H-BF/protos/pkg/api/sgroups"
	model "github.com/H-BF/sgroups/internal/models/sgroups"
	registry "github.com/H-BF/sgroups/internal/registry/sgroups"
	"github.com/pkg/errors"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (srv *sgService) GetSecGroupForAddress(ctx context.Context, req *sg.GetSecGroupForAddressReq) (resp *sg.SecGroup, err error) {
	defer func() {
		err = correctError(err)
	}()
	var queryAddress string
	queryAddress, err = url.PathUnescape(req.GetAddress())
	if err != nil {
		return nil,
			status.Errorf(codes.InvalidArgument, "reason: %v", err)
	}
	var ip net.IP
	if strings.Contains(queryAddress, "/") {
		ip, _, err = net.ParseCIDR(queryAddress)
	} else {
		ip = net.ParseIP(queryAddress)
	}
	if err != nil {
		return nil,
			status.Errorf(codes.InvalidArgument, "reason: %v", err)
	}
	if ip == nil {
		return nil,
			status.Error(codes.InvalidArgument, "invalid request")
	}
	var reader registry.Reader
	if reader, err = srv.registryReader(ctx); err != nil {
		return nil, err
	}
	err = reader.ListSecurityGroups(ctx, func(group model.SecurityGroup) error {
		resp = new(sg.SecGroup)
		resp.Name = group.Name
		for _, nw := range group.Networks {
			resp.Networks = append(resp.Networks,
				&sg.Network{
					Name: nw.Name,
					Network: &common.Networks_NetIP{
						CIDR: nw.Net.String(),
					},
				})
		}
		return errSuccess
	}, registry.IPs(ip, true))
	if err != nil && !errors.Is(err, errSuccess) {
		return nil, status.Errorf(codes.Internal,
			"reason: %v", err)
	}
	if resp == nil {
		return nil, status.Error(codes.NotFound, "not found")
	}
	return resp, nil
}
