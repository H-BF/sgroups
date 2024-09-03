package sgroups

import (
	"net"

	model "github.com/H-BF/sgroups/v2/internal/domains/sgroups"
	registry "github.com/H-BF/sgroups/v2/internal/registry/sgroups"

	"github.com/H-BF/protos/pkg/api/common"
	sg "github.com/H-BF/protos/pkg/api/sgroups"
	"github.com/pkg/errors"
)

type cidrSgRule struct {
	*model.IECidrSgRule
}

type cidrSgRuleIdentity struct {
	*model.IECidrSgRuleIdenity
}

type traffic struct {
	*model.Traffic
}

type ruleAction struct {
	*model.RuleAction
}

func (t traffic) from(src common.Traffic) error {
	switch src {
	case common.Traffic_Egress:
		*t.Traffic = model.EGRESS
	case common.Traffic_Ingress:
		*t.Traffic = model.INGRESS
	default:
		return errors.Errorf("unsupported TRAFFIC value(%v)", src)
	}
	return nil
}

func (a ruleAction) from(src sg.RuleAction) error {
	switch src {
	case sg.RuleAction_UNDEF:
		*a.RuleAction = model.RA_UNDEF
	case sg.RuleAction_DROP:
		*a.RuleAction = model.RA_DROP
	case sg.RuleAction_ACCEPT:
		*a.RuleAction = model.RA_ACCEPT
	default:
		return errors.Errorf("unsupported rule action value(%v)", src)
	}
	return nil
}

func (id cidrSgRuleIdentity) from(src *sg.IECidrSgRule) error {
	ip, ipnet, e := net.ParseCIDR(src.GetCIDR())
	if e != nil {
		return errors.WithMessagef(e, "bad CIDR '%s'", src.GetCIDR())
	}
	if !ipnet.IP.Equal(ip) {
		return errors.Errorf("the '%s' seems just an IP address but not subnet; maybe you will try '%s'",
			src.GetCIDR(), ipnet)
	}
	id.CIDR = *ipnet
	id.SG = src.GetSG()
	e = traffic{Traffic: &id.Traffic}.from(src.GetTraffic())
	if e != nil {
		return e
	}
	e = networkTransport{NetworkTransport: &id.Transport}.from(src.GetTransport())
	if e != nil {
		return e
	}
	return nil
}

func (r cidrSgRule) from(src *sg.IECidrSgRule) error {
	e := cidrSgRuleIdentity{IECidrSgRuleIdenity: &r.ID}.from(src)
	if e != nil {
		return e
	}
	r.Logs = src.GetLogs()
	r.Trace = src.GetTrace()
	e = ruleAction{&r.Action}.from(src.GetAction())
	if e == nil {
		e = ((*rulePorts)(&r.Ports)).from(src.GetPorts())
		if e == nil {
			e = rulePriority{&r.Priority}.from(src.GetPriority())
		}
	}
	return e
}

var syncCidrSgRules = syncAlg[model.IECidrSgRule, *sg.IECidrSgRule]{
	makePrimaryKeyScope: func(rr []model.IECidrSgRule) registry.Scope {
		return registry.PKScopedCidrSgRules(rr...)
	},
	proto2model: func(r *sg.IECidrSgRule) (model.IECidrSgRule, error) {
		var item model.IECidrSgRule
		err := cidrSgRule{IECidrSgRule: &item}.from(r)
		return item, err
	},
}.process
