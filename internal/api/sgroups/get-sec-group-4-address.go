package sgroups

import (
	"context"
	"net"
	"net/url"
	"strings"

	model "github.com/H-BF/sgroups/internal/domains/sgroups"
	registry "github.com/H-BF/sgroups/internal/registry/sgroups"

	sg "github.com/H-BF/protos/pkg/api/sgroups"
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
			status.Errorf(codes.InvalidArgument, "reason: %s", err.Error())
	}
	var ip net.IP
	if strings.Contains(queryAddress, "/") {
		ip, _, err = net.ParseCIDR(queryAddress)
	} else {
		ip = net.ParseIP(queryAddress)
	}
	if err != nil {
		return nil,
			status.Errorf(codes.InvalidArgument, "reason: %s", err.Error())
	}
	if ip == nil {
		return nil,
			status.Error(codes.InvalidArgument, "invalid request: no address is provided")
	}
	var reader registry.Reader
	if reader, err = srv.registryReader(ctx); err != nil {
		return nil, err
	}
	defer reader.Close() //lint:nolint
	var nwName string
	err = reader.ListNetworks(ctx, func(n model.Network) error {
		nwName = n.Name
		return nil
	}, registry.IPs(ip, true))
	if err != nil {
		return nil, err
	}
	if len(nwName) == 0 {
		return nil, status.Errorf(codes.NotFound, "not found SG cause no any subnet for IP(%s)", queryAddress)
	}
	err = reader.ListSecurityGroups(ctx, func(g model.SecurityGroup) error {
		var e error
		if resp, e = sg2proto(g); e != nil {
			return e
		}
		return nil
	}, registry.NetworkNames(nwName))
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, status.Errorf(codes.NotFound, "not found SG for IP(%s)", queryAddress)
	}
	return resp, nil
}
