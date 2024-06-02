package sgroups

import (
	"math"
	"net"

	model "github.com/H-BF/sgroups/internal/models/sgroups"
	registry "github.com/H-BF/sgroups/internal/registry/sgroups"
	"github.com/pkg/errors"

	"github.com/H-BF/protos/pkg/api/common"
	sg "github.com/H-BF/protos/pkg/api/sgroups"
)

type (
	proto2SgIcmpRule struct {
		*model.SgIcmpRule
	}

	proto2SgSgIcmpRule struct {
		*model.SgSgIcmpRule
	}

	proto2IESgSgIcmpRule struct {
		*model.IESgSgIcmpRule
	}

	proto2CidrSgIcmpRule struct {
		*model.IECidrSgIcmpRule
	}
)

func (r proto2SgIcmpRule) from(src *sg.SgIcmpRule) error {
	r.Sg = src.GetSG()
	r.Logs = src.GetLogs()
	r.Trace = src.GetTrace()
	ipv := src.GetICMP().GetIPv()
	switch ipv {
	case common.IpAddrFamily_IPv4:
		r.Icmp.IPv = 4
	case common.IpAddrFamily_IPv6:
		r.Icmp.IPv = 6
	default:
		return errors.Errorf("unrecognized IPv address family (%s)",
			ipv,
		)
	}
	for _, n := range src.GetICMP().GetTypes() {
		if n > uint32(math.MaxUint8) {
			return errors.Errorf("ICMP type(s) must be in [0-255] but we got (%v)", n)
		}
		r.Icmp.Types.Put(uint8(n))
	}
	return ruleAction{&r.Action}.from(src.GetAction())
}

func (r proto2SgSgIcmpRule) from(src *sg.SgSgIcmpRule) error {
	r.SgFrom = src.GetSgFrom()
	r.SgTo = src.GetSgTo()
	r.Logs = src.GetLogs()
	r.Trace = src.GetTrace()
	ipv := src.GetICMP().GetIPv()
	switch ipv {
	case common.IpAddrFamily_IPv4:
		r.Icmp.IPv = 4
	case common.IpAddrFamily_IPv6:
		r.Icmp.IPv = 6
	default:
		return errors.Errorf("unrecognized IPv address family (%s)",
			ipv,
		)
	}
	for _, n := range src.GetICMP().GetTypes() {
		if n > uint32(math.MaxUint8) {
			return errors.Errorf("ICMP type(s) must be in [0-255] but we got (%v)", n)
		}
		r.Icmp.Types.Put(uint8(n))
	}
	e := ruleAction{&r.Action}.from(src.GetAction())
	if e == nil {
		e = rulePriority{&r.Priority}.from(src.GetPriority())
	}
	return e
}

func (r proto2IESgSgIcmpRule) from(src *sg.IESgSgIcmpRule) error {
	r.SgLocal = src.GetSgLocal()
	r.Sg = src.GetSG()
	r.Logs = src.GetLogs()
	r.Trace = src.GetTrace()

	e := traffic{Traffic: &r.Traffic}.from(src.GetTraffic())
	if e != nil {
		return e
	}

	ipv := src.GetICMP().GetIPv()
	switch ipv {
	case common.IpAddrFamily_IPv4:
		r.Icmp.IPv = 4
	case common.IpAddrFamily_IPv6:
		r.Icmp.IPv = 6
	default:
		return errors.Errorf("unrecognized IPv address family (%s)",
			ipv,
		)
	}
	for _, n := range src.GetICMP().GetTypes() {
		if n > uint32(math.MaxUint8) {
			return errors.Errorf("ICMP type(s) must be in [0-255] but we got (%v)", n)
		}
		r.Icmp.Types.Put(uint8(n))
	}
	e = ruleAction{&r.Action}.from(src.GetAction())
	if e == nil {
		e = rulePriority{&r.Priority}.from(src.GetPriority())
	}
	return e
}

func (r proto2CidrSgIcmpRule) from(src *sg.IECidrSgIcmpRule) error {
	ip, ipnet, e := net.ParseCIDR(src.GetCIDR())
	if e != nil {
		return errors.WithMessagef(e, "bad CIDR '%s'", src.GetCIDR())
	}
	if !ipnet.IP.Equal(ip) {
		return errors.Errorf("the '%s' seems just an IP address but not subnet; maybe you will try '%s'",
			src.GetCIDR(), ipnet)
	}
	r.CIDR = *ipnet
	r.SG = src.GetSG()
	r.Logs = src.GetLogs()
	r.Trace = src.GetTrace()

	e = traffic{Traffic: &r.Traffic}.from(src.GetTraffic())
	if e != nil {
		return e
	}

	ipv := src.GetICMP().GetIPv()
	switch ipv {
	case common.IpAddrFamily_IPv4:
		r.Icmp.IPv = 4
	case common.IpAddrFamily_IPv6:
		r.Icmp.IPv = 6
	default:
		return errors.Errorf("unrecognized IPv address family (%s)",
			ipv,
		)
	}
	for _, n := range src.GetICMP().GetTypes() {
		if n > uint32(math.MaxUint8) {
			return errors.Errorf("ICMP type(s) must be in [0-255] but we got (%v)", n)
		}
		r.Icmp.Types.Put(uint8(n))
	}
	e = ruleAction{&r.Action}.from(src.GetAction())
	if e == nil {
		e = rulePriority{&r.Priority}.from(src.GetPriority())
	}
	return e
}

var syncSgIcmpRule = syncAlg[model.SgIcmpRule, *sg.SgIcmpRule]{
	makePrimaryKeyScope: func(r []model.SgIcmpRule) registry.Scope {
		return registry.PKScopeOfSgIcmpRules(r...)
	},
	proto2model: func(r *sg.SgIcmpRule) (model.SgIcmpRule, error) {
		var ret model.SgIcmpRule
		err := proto2SgIcmpRule{&ret}.from(r)
		return ret, err
	},
}.process

var syncSgSgIcmpRule = syncAlg[model.SgSgIcmpRule, *sg.SgSgIcmpRule]{
	makePrimaryKeyScope: func(r []model.SgSgIcmpRule) registry.Scope {
		return registry.PKScopeOfSgSgIcmpRules(r...)
	},
	proto2model: func(r *sg.SgSgIcmpRule) (model.SgSgIcmpRule, error) {
		var ret model.SgSgIcmpRule
		err := proto2SgSgIcmpRule{&ret}.from(r)
		return ret, err
	},
}.process

var syncIESgSgIcmpRule = syncAlg[model.IESgSgIcmpRule, *sg.IESgSgIcmpRule]{
	makePrimaryKeyScope: func(r []model.IESgSgIcmpRule) registry.Scope {
		return registry.PKScopedIESgSgRules(r...)
	},
	proto2model: func(r *sg.IESgSgIcmpRule) (ret model.IESgSgIcmpRule, err error) {
		err = proto2IESgSgIcmpRule{&ret}.from(r)
		return ret, err
	},
}.process

var syncIECidrSgIcmpRule = syncAlg[model.IECidrSgIcmpRule, *sg.IECidrSgIcmpRule]{
	makePrimaryKeyScope: func(r []model.IECidrSgIcmpRule) registry.Scope {
		return registry.PKScopedCidrSgIcmpRules(r...)
	},
	proto2model: func(r *sg.IECidrSgIcmpRule) (ret model.IECidrSgIcmpRule, err error) {
		err = proto2CidrSgIcmpRule{&ret}.from(r)
		return ret, err
	},
}.process
