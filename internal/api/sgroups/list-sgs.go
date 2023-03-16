package sgroups

import (
	"context"

	"github.com/H-BF/sgroups/internal/models/sgroups"
	registry "github.com/H-BF/sgroups/internal/registry/sgroups"

	sg "github.com/H-BF/protos/pkg/api/sgroups"
)

// ListSecurityGroups impl 'sgrpups' service
func (srv *sgService) ListSecurityGroups(ctx context.Context, _ *sg.ListSecurityGroupsReq) (resp *sg.ListSecurityGroupsResp, err error) {
	defer func() {
		err = correctError(err)
	}()
	var reader registry.Reader
	if reader, err = srv.registryReader(ctx); err != nil {
		return resp, err
	}
	resp = new(sg.ListSecurityGroupsResp)
	err = reader.ListSecurityGroups(ctx, func(group sgroups.SecurityGroup) error {
		g := sg.SecGroup{Name: group.Name}
		for _, nw := range group.Networks {
			g.Networks = append(g.Networks, &sg.Network{Name: nw.Name})
		}
		resp.Groups = append(resp.Groups, &g)
		return nil
	}, registry.NoScope)
	return resp, err
}
