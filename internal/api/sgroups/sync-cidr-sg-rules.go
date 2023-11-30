package sgroups

import (
	"net"

	model "github.com/H-BF/sgroups/internal/models/sgroups"
	registry "github.com/H-BF/sgroups/internal/registry/sgroups"

	"github.com/H-BF/protos/pkg/api/common"
	sg "github.com/H-BF/protos/pkg/api/sgroups"
	"github.com/pkg/errors"
)

type cidrSgRule struct {
	*model.CidrSgRule
}

type cidrSgRuleIdentity struct {
	*model.CidrSgRuleIdenity
}

type traffic struct {
	*model.Traffic
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

func (id cidrSgRuleIdentity) from(src *sg.CidrSgRule) error {
	_, ipnet, e := net.ParseCIDR(src.GetCIDR())
	if e != nil {
		return errors.WithMessagef(e, "bad CIDR '%s'", src.GetCIDR())
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

func (r cidrSgRule) from(src *sg.CidrSgRule) error {
	e := cidrSgRuleIdentity{CidrSgRuleIdenity: &r.ID}.from(src)
	if e != nil {
		return e
	}
	r.Logs = src.GetLogs()
	r.Trace = src.GetTrace()
	e = ((*rulePorts)(&r.Ports)).from(src.GetPorts())
	return e
}

var syncCidrSgRules = syncAlg[model.CidrSgRule, *sg.CidrSgRule]{
	makePrimaryKeyScope: func(rr []model.CidrSgRule) registry.Scope {
		return registry.PKScopedCidrSgRules(rr...)
	},
	proto2model: func(r *sg.CidrSgRule) (model.CidrSgRule, error) {
		var item model.CidrSgRule
		err := cidrSgRule{CidrSgRule: &item}.from(r)
		return item, err
	},
}.process
