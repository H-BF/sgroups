package sgroups

import (
	"context"

	model "github.com/H-BF/sgroups/internal/models/sgroups"
	registry "github.com/H-BF/sgroups/internal/registry/sgroups"

	"github.com/H-BF/protos/pkg/api/common"
	sg "github.com/H-BF/protos/pkg/api/sgroups"
	"github.com/pkg/errors"
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
	sgName := req.GetSgName()
	if len(sgName) == 0 {
		status.Error(codes.InvalidArgument, "security group name is not provided by request")
	}
	err = reader.ListSecurityGroups(ctx, func(group model.SecurityGroup) error {
		resp = new(sg.GetSgSubnetsResp)
		for _, n := range group.Networks {
			resp.Networks = append(resp.Networks,
				&sg.Network{
					Name: n.Name,
					Network: &common.Networks_NetIP{
						CIDR: n.Net.String(),
					},
				})
		}
		return errSuccess
	}, registry.SG(sgName))

	if err != nil && !errors.Is(err, errSuccess) {
		return nil, status.Errorf(codes.Internal, "reason: %v", err)
	}
	if resp == nil {
		return nil, status.Errorf(codes.NotFound,
			"SG '%s' not found", sgName)
	}
	if len(resp.GetNetworks()) == 0 {
		return nil, status.Errorf(codes.NotFound,
			"no any subnet found for SG '%s'", sgName)
	}
	return resp, nil
}
