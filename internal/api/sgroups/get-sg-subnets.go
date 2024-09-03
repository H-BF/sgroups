package sgroups

import (
	"context"

	model "github.com/H-BF/sgroups/v2/internal/domains/sgroups"
	registry "github.com/H-BF/sgroups/v2/internal/registry/sgroups"

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
	var gr *model.SecurityGroup
	err = reader.ListSecurityGroups(ctx, func(group model.SecurityGroup) error {
		gr = &group
		return nil
	}, registry.SG(sgName))
	if err != nil {
		return nil, err
	}
	if gr == nil {
		return nil, status.Errorf(codes.NotFound, "SG '%s' is not found", sgName)
	}
	resp = new(sg.GetSgSubnetsResp)
	if gr.Networks.Len() > 0 {
		err = reader.ListNetworks(ctx, func(n model.Network) error {
			resp.Networks = append(resp.Networks,
				&sg.Network{
					Name: n.Name,
					Network: &common.Networks_NetIP{
						CIDR: n.Net.String(),
					},
				})
			return nil
		}, registry.NetworkNames(gr.Networks.Values()...))
		if err != nil {
			return nil, err
		}
	}
	if len(resp.GetNetworks()) == 0 {
		return nil, status.Errorf(codes.NotFound, "no any subnet found for SG '%s'", sgName)
	}
	return resp, nil
}
