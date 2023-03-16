package sgroups

import (
	"context"

	"github.com/H-BF/sgroups/internal/models/sgroups"
	registry "github.com/H-BF/sgroups/internal/registry/sgroups"

	"github.com/H-BF/protos/pkg/api/common"
	sg "github.com/H-BF/protos/pkg/api/sgroups"
)

// ListNetworks impl 'sgroups' service
func (srv *sgService) ListNetworks(ctx context.Context, _ *sg.ListNetworksReq) (resp *sg.ListNetworksResp, err error) {
	defer func() {
		err = correctError(err)
	}()
	var reader registry.Reader
	if reader, err = srv.registryReader(ctx); err != nil {
		return resp, err
	}
	resp = new(sg.ListNetworksResp)
	err = reader.ListNetworks(ctx, func(nw sgroups.Network) error {
		resp.Networks = append(resp.Networks, &sg.Network{
			Name: nw.Name,
			Network: &common.Networks_NetIP{
				CIDR: nw.Net.String(),
			},
		})
		return nil
	}, registry.NoScope)
	return resp, err
}
