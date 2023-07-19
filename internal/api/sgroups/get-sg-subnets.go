package sgroups

import (
	"context"
	"errors"

	model "github.com/H-BF/sgroups/internal/models/sgroups"
	registry "github.com/H-BF/sgroups/internal/registry/sgroups"

	"github.com/H-BF/protos/pkg/api/common"
	sg "github.com/H-BF/protos/pkg/api/sgroups"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (srv *sgService) GetSgSubnets(ctx context.Context, req *sg.GetSgSubnetsReq) (resp *sg.GetSgSubnetsResp, err error) {
	defer func() {
		err = correctError(err)
	}()
	var reader registry.Reader
	if reader, err = srv.registryReader(ctx); err != nil {
		return nil, err
	}
	defer reader.Close() //lint:nolint
	sgName := req.GetSgName()
	if len(sgName) == 0 {
		return nil, status.Error(codes.InvalidArgument, "SG name is not provided by request")
	}
	err = reader.ListSecurityGroups(ctx, func(group model.SecurityGroup) error {
		resp = new(sg.GetSgSubnetsResp)
		if len(group.Networks) > 0 {
			e := reader.ListNetworks(ctx, func(n model.Network) error {
				resp.Networks = append(resp.Networks,
					&sg.Network{
						Name: n.Name,
						Network: &common.Networks_NetIP{
							CIDR: n.Net.String(),
						},
					})
				return nil
			}, registry.NetworkNames(group.Networks[0], group.Networks[1:]...))
			if e != nil {
				return e
			}
		}
		return errSuccess
	}, registry.SG(sgName))
	if errors.Is(err, errSuccess) {
		if len(resp.Networks) == 0 {
			return nil, status.Errorf(codes.NotFound, "no any subnet found for SG '%s'", sgName)
		}
		return resp, nil
	}
	if err == nil {
		return nil, status.Errorf(codes.NotFound, "SG '%s' is not found", sgName)
	}
	return nil, status.Errorf(codes.Internal, "reason: %s", err.Error())
}
