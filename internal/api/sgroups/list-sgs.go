package sgroups

import (
	"context"

	"github.com/H-BF/sgroups/internal/models/sgroups"
	registry "github.com/H-BF/sgroups/internal/registry/sgroups"

	"github.com/H-BF/protos/pkg/api/common"
	sg "github.com/H-BF/protos/pkg/api/sgroups"
)

// ListSecurityGroups impl 'sgrpups' service
func (srv *sgService) ListSecurityGroups(ctx context.Context, req *sg.ListSecurityGroupsReq) (resp *sg.ListSecurityGroupsResp, err error) {
	defer func() {
		err = correctError(err)
	}()
	var reader registry.Reader
	if reader, err = srv.registryReader(ctx); err != nil {
		return resp, err
	}
	var scope registry.Scope = registry.NoScope
	if names := req.GetSgNames(); len(names) > 0 {
		scope = registry.SG(names[0], names[1:]...)
	}
	resp = new(sg.ListSecurityGroupsResp)
	err = reader.ListSecurityGroups(ctx, func(group sgroups.SecurityGroup) error {
		g := sg.SecGroup{Name: group.Name}
		for _, nw := range group.Networks {
			g.Networks = append(g.Networks, &sg.Network{
				Name: nw.Name,
				Network: &common.Networks_NetIP{
					CIDR: nw.Net.String(),
				},
			})
		}
		resp.Groups = append(resp.Groups, &g)
		return nil
	}, scope)
	return resp, err
}
