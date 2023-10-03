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
	syncFqdnRules struct {
		wr    registry.Writer
		rules []*sg.FqdnRule
		ops   sg.SyncReq_SyncOp
	}

	sgFqdnRule struct {
		*model.FQDNRule
	}

	sgFqdnRuleIdentity struct {
		*model.FQDNRuleIdentity
	}
)

func (snc syncFqdnRules) process(ctx context.Context) error { //nolint:dupl
	rules := make([]model.FQDNRule, 0, len(snc.rules))
	for _, rl := range snc.rules {
		var item model.FQDNRule
		if err := (sgFqdnRule{FQDNRule: &item}).from(rl); err != nil {
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
		sc = registry.FQDNRule(rules...)
		rules = nil
	}
	return snc.wr.SyncFqdnRules(ctx, rules, sc, opts...)
}

func (ri sgFqdnRuleIdentity) from(src *sg.FqdnRule) error {
	ri.SgFrom = src.GetSgFrom()
	ri.FqdnTo = model.FQDN(src.GetFQDN())
	return networkTransport{NetworkTransport: &ri.Transport}.
		from(src.GetTransport())
}

func (r sgFqdnRule) from(src *sg.FqdnRule) error {
	err := sgFqdnRuleIdentity{FQDNRuleIdentity: &r.ID}.
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
