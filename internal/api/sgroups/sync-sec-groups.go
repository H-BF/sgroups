package sgroups

import (
	"context"

	sg "github.com/H-BF/protos/pkg/api/sgroups"
	model "github.com/H-BF/sgroups/internal/models/sgroups"
	registry "github.com/H-BF/sgroups/internal/registry/sgroups"
)

type syncGroups struct {
	srv    *sgService
	groups []*sg.SecGroup
	ops    sg.SyncReq_SyncOp
}

func (snc syncGroups) process(ctx context.Context) error {
	names := make([]string, 0, len(snc.groups))
	groups := make([]model.SecurityGroup, 0, len(snc.groups))
	var opts []registry.Option
	var sc registry.Scope = registry.NoScope
	for _, g := range snc.groups {
		var x securityGroup
		x.from(g)
		groups = append(groups, x.SecurityGroup)
		if snc.ops != sg.SyncReq_FullSync {
			names = append(names, g.GetName())
		}
	}
	if len(names) != 0 {
		sc = registry.SG(names[0], names[1:]...)
	}
	if err := syncOptionsFromProto(snc.ops, &opts); err != nil {
		return err
	}
	writer := snc.srv.registryWriter()
	return writer.SyncSecurityGroups(ctx, groups, sc, opts...)
}

type securityGroup struct {
	model.SecurityGroup
}

func (n *securityGroup) from(g *sg.SecGroup) {
	n.Name = g.GetName()
	for _, nw := range g.GetNetworks() {
		n.Networks = append(n.Networks, model.Network{Name: nw.GetName()})
	}
}
