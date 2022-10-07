package sgroups

import (
	"context"

	"github.com/H-BF/protos/pkg/api/common"
	sg "github.com/H-BF/protos/pkg/api/sgroups"
	model "github.com/H-BF/sgroups/internal/models/sgroups"
	registry "github.com/H-BF/sgroups/internal/registry/sgroups"
	"github.com/pkg/errors"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (srv *sgService) GetSgSubnets(ctx context.Context, req *sg.GetSgSubnetsReq) (resp *sg.GetSgSubnetsResp, err error) {
	reader := srv.registryReader()
	defer func() {
		err = correctError(err)
	}()
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
	}, registry.SG(req.GetSgName()))

	if err != nil && !errors.Is(err, errSuccess) {
		return nil, status.Errorf(codes.Internal, "reason: %v", err)
	}
	if resp == nil {
		return nil, status.Error(codes.NotFound, "not found")
	}
	return resp, nil
}
