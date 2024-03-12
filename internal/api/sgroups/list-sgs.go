package sgroups

import (
	"context"

	"github.com/H-BF/sgroups/internal/models/sgroups"
	registry "github.com/H-BF/sgroups/internal/registry/sgroups"

	sg "github.com/H-BF/protos/pkg/api/sgroups"
	"github.com/pkg/errors"
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
	defer reader.Close() //lint:nolint
	var scope registry.Scope = registry.NoScope
	if names := req.GetSgNames(); len(names) > 0 {
		scope = registry.SG(names...)
	}
	resp = new(sg.ListSecurityGroupsResp)
	err = reader.ListSecurityGroups(ctx, func(group sgroups.SecurityGroup) error {
		sg, e := sg2proto(group)
		if e != nil {
			return e
		}
		resp.Groups = append(resp.Groups, sg)
		return nil
	}, scope)
	return resp, err
}

func sgDefaultAction2proto(m sgroups.ChainDefaultAction) (ret sg.DefaultAction, err error) {
	switch m {
	case sgroups.DEFAULT:
		ret = sg.DefaultAction_DEFAULT
	case sgroups.ACCEPT:
		ret = sg.DefaultAction_ACCEPT
	case sgroups.DROP:
		ret = sg.DefaultAction_DROP
	default:
		err = errors.Errorf("unsupported SG chain default action (%v) ", m)
	}
	return ret, err
}

func sg2proto(m sgroups.SecurityGroup) (*sg.SecGroup, error) {
	ret := sg.SecGroup{
		Name:     m.Name,
		Networks: m.Networks,
		Logs:     m.Logs,
		Trace:    m.Trace,
	}
	var e error
	ret.DefaultAction, e = sgDefaultAction2proto(m.DefaultAction)
	return &ret, e
}
