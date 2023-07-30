package sgroups

import (
	"context"

	model "github.com/H-BF/sgroups/internal/models/sgroups"
	registry "github.com/H-BF/sgroups/internal/registry/sgroups"

	sg "github.com/H-BF/protos/pkg/api/sgroups"
)

type syncGroups struct {
	wr     registry.Writer
	groups []*sg.SecGroup
	ops    sg.SyncReq_SyncOp
}

func (snc syncGroups) process(ctx context.Context) error {
	var names []string
	var groups []model.SecurityGroup
	for _, g := range snc.groups {
		if snc.ops == sg.SyncReq_Delete {
			if names == nil {
				names = make([]string, 0, len(snc.groups))
			}
			names = append(names, g.GetName())
		} else {
			if groups == nil {
				groups = make([]model.SecurityGroup, 0, len(snc.groups))
			}
			var x securityGroup
			x.from(g)
			groups = append(groups, x.SecurityGroup)
		}
	}
	var sc registry.Scope = registry.NoScope
	if snc.ops == sg.SyncReq_Delete {
		sc = registry.SG(names...)
	}
	var opts []registry.Option
	if err := syncOptionsFromProto(snc.ops, &opts); err != nil {
		return err
	}
	return snc.wr.SyncSecurityGroups(ctx, groups, sc, opts...)
}

type securityGroup struct {
	model.SecurityGroup
}

func (n *securityGroup) from(g *sg.SecGroup) {
	n.Name = g.GetName()
	n.Networks = g.GetNetworks()
}
