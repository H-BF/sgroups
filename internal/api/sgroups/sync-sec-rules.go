package sgroups

import (
	"fmt"
	"math"

	model "github.com/H-BF/sgroups/internal/models/sgroups"
	registry "github.com/H-BF/sgroups/internal/registry/sgroups"

	"github.com/H-BF/protos/pkg/api/common"
	sg "github.com/H-BF/protos/pkg/api/sgroups"
	"github.com/pkg/errors"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type rulePorts []model.SGRulePorts

type sgRule struct {
	*model.SGRule
}

type sgRuleIdentity struct {
	*model.SGRuleIdentity
}

type networkTransport struct {
	*model.NetworkTransport
}

type rulePriority struct {
	*model.RulePriority
}

func (nt networkTransport) from(src common.Networks_NetIP_Transport) error {
	switch src {
	case common.Networks_NetIP_TCP:
		*nt.NetworkTransport = model.TCP
	case common.Networks_NetIP_UDP:
		*nt.NetworkTransport = model.UDP
	default:
		return status.Errorf(codes.InvalidArgument,
			"bad IP proto (%v)", src)
	}
	return nil
}

func (r *rulePorts) from(src []*sg.AccPorts) error {
	for _, p := range src {
		var item model.SGRulePorts
		var e error
		if item.S, e = model.PortSource(p.S).ToPortRanges(); e != nil {
			return errors.WithMessagef(e, "bad 'source' port(s) '%s'", p.S)
		}
		if item.D, e = model.PortSource(p.D).ToPortRanges(); e != nil {
			return errors.WithMessagef(e, "bad 'dest' port(s) '%s'", p.D)
		}
		*r = append(*r, item)
	}
	return nil
}

func (ri sgRuleIdentity) from(src *sg.SgSgRule) error {
	ri.SgFrom = src.GetSgFrom()
	ri.SgTo = src.GetSgTo()
	return networkTransport{NetworkTransport: &ri.Transport}.
		from(src.GetTransport())
}

func (r sgRule) from(src *sg.SgSgRule) error {
	err := sgRuleIdentity{SGRuleIdentity: &r.ID}.
		from(src)
	if err == nil {
		err = rulePriority{&r.Priority}.from(src.GetPriority())
	}
	if err == nil {
		r.Logs = src.GetLogs()
		var p rulePorts
		err = ruleAction{&r.Action}.from(src.GetAction())
		if err != nil {
			return err
		}
		if err = p.from(src.GetPorts()); err == nil {
			r.Ports = p
		}
	}
	return err
}

func (p rulePriority) from(src *sg.RulePriority) error {
	switch t := src.GetValue().(type) {
	case *sg.RulePriority_Some:
		if !(math.MinInt16 <= t.Some && t.Some <= math.MaxInt16) {
			return errors.Errorf("rule priority (%v) is out of range [%v, %v]",
				t.Some, math.MinInt16, math.MaxInt16)
		}
		p.Set(int16(t.Some))
	case nil:
		p.Unset()
	default:
		return fmt.Errorf("unsupported rule-priority value(%v)", t)
	}
	return nil
}

var syncSGRules = syncAlg[model.SGRule, *sg.SgSgRule]{
	makePrimaryKeyScope: func(rr []model.SGRule) registry.Scope {
		return registry.PKScopeOfSGRules(rr...)
	},
	proto2model: func(r *sg.SgSgRule) (model.SGRule, error) {
		var item model.SGRule
		err := sgRule{SGRule: &item}.from(r)
		return item, err
	},
}.process
