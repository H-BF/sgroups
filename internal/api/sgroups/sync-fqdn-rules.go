package sgroups

import (
	"github.com/H-BF/sgroups/internal/dict"
	model "github.com/H-BF/sgroups/internal/models/sgroups"
	registry "github.com/H-BF/sgroups/internal/registry/sgroups"

	sg "github.com/H-BF/protos/pkg/api/sgroups"
)

type (
	sgFqdnRule struct {
		*model.FQDNRule
	}
	sgFqdnRuleIdentity struct {
		*model.FQDNRuleIdentity
	}
)

func (ri sgFqdnRuleIdentity) from(src *sg.FqdnRule) error {
	ri.SgFrom = src.GetSgFrom()
	ri.FqdnTo = model.FQDN(src.GetFQDN())
	return networkTransport{NetworkTransport: &ri.Transport}.
		from(src.GetTransport())
}

func (r sgFqdnRule) from(src *sg.FqdnRule) error {
	for _, p := range src.GetProtocols() {
		_ = r.NdpiProtocols.Insert(dict.StringCiKey(p))
	}
	err := sgFqdnRuleIdentity{FQDNRuleIdentity: &r.ID}.
		from(src)
	if err == nil {
		err = rulePriority{&r.Priority}.from(src.GetPriority())
	}
	if err == nil {
		r.Logs = src.GetLogs()
		err = ruleAction{RuleAction: &r.Action}.from(src.GetAction())
		if err != nil {
			return err
		}
		var p rulePorts
		if err = p.from(src.GetPorts()); err == nil {
			r.Ports = p
		}
	}
	return err
}

var syncFQDNRules = syncAlg[model.FQDNRule, *sg.FqdnRule]{
	makePrimaryKeyScope: func(rr []model.FQDNRule) registry.Scope {
		return registry.PKScopeOfFQDNRules(rr...)
	},
	proto2model: func(r *sg.FqdnRule) (model.FQDNRule, error) {
		var item model.FQDNRule
		err := sgFqdnRule{FQDNRule: &item}.from(r)
		return item, err
	},
}.process
