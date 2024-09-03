package sgroups

import (
	model "github.com/H-BF/sgroups/v2/internal/domains/sgroups"
	registry "github.com/H-BF/sgroups/v2/internal/registry/sgroups"

	sg "github.com/H-BF/protos/pkg/api/sgroups"
	"github.com/pkg/errors"
)

type securityGroup struct {
	model.SecurityGroup
}

func (n *securityGroup) from(g *sg.SecGroup) error {
	n.Name = g.GetName()
	n.Networks.PutMany(g.GetNetworks()...)
	n.Logs = g.GetLogs()
	n.Trace = g.GetTrace()
	switch g.GetDefaultAction() {
	case sg.SecGroup_DEFAULT:
		n.DefaultAction = model.DEFAULT
	case sg.SecGroup_DROP:
		n.DefaultAction = model.DROP
	case sg.SecGroup_ACCEPT:
		n.DefaultAction = model.ACCEPT
	default:
		return errors.Errorf("unsupported SG chain default action ('%s')", g.GetDefaultAction())
	}
	return nil
}

var syncSecurityGroups = syncAlg[model.SecurityGroup, *sg.SecGroup]{
	makePrimaryKeyScope: func(sgs []model.SecurityGroup) registry.Scope {
		names := make([]string, 0, len(sgs))
		for _, sg := range sgs {
			names = append(names, sg.Name)
		}
		return registry.SG(names...)
	},
	proto2model: func(sg *sg.SecGroup) (model.SecurityGroup, error) {
		var x securityGroup
		err := x.from(sg)
		return x.SecurityGroup, err
	},
}.process
