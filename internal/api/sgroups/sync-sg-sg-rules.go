package sgroups

import (
	sg "github.com/H-BF/protos/pkg/api/sgroups"
	model "github.com/H-BF/sgroups/internal/models/sgroups"
	registry "github.com/H-BF/sgroups/internal/registry/sgroups"
)

type (
	sgSgRule struct {
		*model.SgSgRule
	}

	sgSgRuleIdentity struct {
		*model.SgSgRuleIdentity
	}
)

func (id sgSgRuleIdentity) from(src *sg.SgSgRule) error {
	id.SgLocal = src.GetSgLocal()
	id.Sg = src.GetSg()

	e := traffic{Traffic: &id.Traffic}.from(src.GetTraffic())
	if e != nil {
		return e
	}
	e = networkTransport{NetworkTransport: &id.Transport}.from(src.GetTransport())
	if e != nil {
		return e
	}
	return nil
}

func (r sgSgRule) from(src *sg.SgSgRule) error {
	e := sgSgRuleIdentity{SgSgRuleIdentity: &r.ID}.from(src)
	if e != nil {
		return e
	}
	r.Logs = src.GetLogs()
	r.Trace = src.GetTrace()
	e = ((*rulePorts)(&r.Ports)).from(src.GetPorts())
	return e
}

var syncSgSgRules = syncAlg[model.SgSgRule, *sg.SgSgRule]{
	makePrimaryKeyScope: func(rr []model.SgSgRule) registry.Scope {
		return registry.PKScopedSgSgRules(rr...)
	},
	proto2model: func(r *sg.SgSgRule) (ret model.SgSgRule, err error) {
		err = sgSgRule{SgSgRule: &ret}.from(r)
		return
	},
}.process
