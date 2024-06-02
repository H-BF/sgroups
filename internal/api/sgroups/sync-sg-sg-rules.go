package sgroups

import (
	sg "github.com/H-BF/protos/pkg/api/sgroups"
	model "github.com/H-BF/sgroups/internal/models/sgroups"
	registry "github.com/H-BF/sgroups/internal/registry/sgroups"
)

type (
	sgSgRule struct {
		*model.IESgSgRule
	}

	sgSgRuleIdentity struct {
		*model.IESgSgRuleIdentity
	}
)

func (id sgSgRuleIdentity) from(src *sg.IESgSgRule) error {
	id.SgLocal = src.GetSgLocal()
	id.Sg = src.GetSG()

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

func (r sgSgRule) from(src *sg.IESgSgRule) error {
	e := sgSgRuleIdentity{IESgSgRuleIdentity: &r.ID}.from(src)
	if e != nil {
		return e
	}
	r.Logs = src.GetLogs()
	r.Trace = src.GetTrace()
	e = ruleAction{&r.Action}.from(src.GetAction())
	if e != nil {
		return e
	}
	e = ((*rulePorts)(&r.Ports)).from(src.GetPorts())
	if e == nil {
		e = rulePriority{&r.Priority}.from(src.GetPriority())
	}
	return e
}

var syncSgSgRules = syncAlg[model.IESgSgRule, *sg.IESgSgRule]{
	makePrimaryKeyScope: func(rr []model.IESgSgRule) registry.Scope {
		return registry.PKScopedSgSgRules(rr...)
	},
	proto2model: func(r *sg.IESgSgRule) (ret model.IESgSgRule, err error) {
		err = sgSgRule{IESgSgRule: &ret}.from(r)
		return
	},
}.process
