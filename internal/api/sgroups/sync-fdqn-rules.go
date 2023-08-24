package sgroups

import (
	"context"

	model "github.com/H-BF/sgroups/internal/models/sgroups"
	registry "github.com/H-BF/sgroups/internal/registry/sgroups"

	sg "github.com/H-BF/protos/pkg/api/sgroups"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type (
	syncFdqnRules struct {
		wr    registry.Writer
		rules []*sg.FdqnRule
		ops   sg.SyncReq_SyncOp
	}

	sgFdqnRule struct {
		*model.FDQNRule
	}

	sgFdqnRuleIdentity struct {
		*model.FDQNRuleIdentity
	}
)

func (snc syncFdqnRules) process(ctx context.Context) error {
	rules := make([]model.FDQNRule, 0, len(snc.rules))
	for _, rl := range snc.rules {
		var item model.FDQNRule
		if err := (sgFdqnRule{FDQNRule: &item}).from(rl); err != nil {
			return status.Error(codes.InvalidArgument, err.Error())
		}
		rules = append(rules, item)
	}
	var opts []registry.Option
	if err := syncOptionsFromProto(snc.ops, &opts); err != nil {
		return status.Error(codes.InvalidArgument, err.Error())
	}
	var sc registry.Scope = registry.NoScope
	if snc.ops == sg.SyncReq_Delete {
		sc = registry.FDQNRule(rules...)
		rules = nil
	}
	return snc.wr.SyncFdqnRules(ctx, rules, sc, opts...)
}

func (ri sgFdqnRuleIdentity) from(src *sg.FdqnRule) error {
	ri.SgFrom = src.GetSgFrom()
	return networkTransport{NetworkTransport: &ri.Transport}.
		from(src.GetTransport())
}

func (r sgFdqnRule) from(src *sg.FdqnRule) error {
	err := sgFdqnRuleIdentity{FDQNRuleIdentity: &r.ID}.
		from(src)
	if err == nil {
		r.Logs = src.GetLogs()
		var p rulePorts
		if err = p.from(src.GetPorts()); err == nil {
			r.Ports = p
		}
	}
	return err
}
