package sgroups

import (
	"context"

	model "github.com/H-BF/sgroups/internal/models/sgroups"
	registry "github.com/H-BF/sgroups/internal/registry/sgroups"

	"github.com/H-BF/protos/pkg/api/common"
	sg "github.com/H-BF/protos/pkg/api/sgroups"
	"github.com/pkg/errors"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func netTranport2proto(src model.NetworkTransport) (common.Networks_NetIP_Transport, error) {
	switch src {
	case model.TCP:
		return common.Networks_NetIP_TCP, nil
	case model.UDP:
		return common.Networks_NetIP_UDP, nil
	}
	return 0, errors.Errorf("bad net transport (%v)", src)
}

func traffic2proto(src model.Traffic) (common.Traffic, error) {
	switch src {
	case model.EGRESS:
		return common.Traffic_Egress, nil
	case model.INGRESS:
		return common.Traffic_Ingress, nil
	}
	return 0, errors.Errorf("bad traffic value (%v)", src)
}

func sgAccPorts2proto(src []model.SGRulePorts) ([]*sg.AccPorts, error) {
	ret := make([]*sg.AccPorts, 0, len(src))
	for _, p := range src {
		var s, d model.PortSource
		if err := s.FromPortRanges(p.S); err != nil {
			return nil, errors.Wrapf(err, "bad 'S' ports value '%s'", p.S)
		}
		if err := d.FromPortRanges(p.D); err != nil {
			return nil, errors.Wrapf(err, "bad 'D' ports value '%s'", p.D)
		}
		ret = append(ret, &sg.AccPorts{S: string(s), D: string(d)})
	}
	return ret, nil
}

func sgRule2proto(src model.SGRule) (*sg.Rule, error) {
	var ret sg.Rule
	if t, e := netTranport2proto(src.ID.Transport); e != nil {
		return nil, e
	} else {
		ret.Transport = t
	}
	ret.Logs = src.Logs
	ret.SgFrom = src.ID.SgFrom
	ret.SgTo = src.ID.SgTo
	var e error
	ret.Ports, e = sgAccPorts2proto(src.Ports)
	return &ret, e
}

func sgFqdnRule2proto(src model.FQDNRule) (*sg.FqdnRule, error) {
	var ret sg.FqdnRule
	if t, e := netTranport2proto(src.ID.Transport); e != nil {
		return nil, e
	} else {
		ret.Transport = t
	}
	ret.Logs = src.Logs
	ret.SgFrom = src.ID.SgFrom
	ret.FQDN = src.ID.FqdnTo.String()
	var e error
	ret.Ports, e = sgAccPorts2proto(src.Ports)
	return &ret, e
}

func sgIcmpRule2proto(src model.SgIcmpRule) (*sg.SgIcmpRule, error) {
	ret := sg.SgIcmpRule{
		ICMP: new(common.ICMP),
	}
	ret.Logs = src.Logs
	ret.Trace = src.Trace
	ret.Sg = src.Sg
	switch src.Icmp.IPv {
	case model.IPv4:
		ret.ICMP.IPv = common.IpAddrFamily_IPv4
	case model.IPv6:
		ret.ICMP.IPv = common.IpAddrFamily_IPv6
	default:
		return nil, errors.Errorf("got unsupported IPv(%v)", src.Icmp.IPv)
	}
	src.Icmp.Types.Iterate(func(t uint8) bool {
		ret.ICMP.Types = append(ret.ICMP.Types, uint32(t))
		return true
	})
	return &ret, nil
}

func sgSgIcmpRule2proto(src model.SgSgIcmpRule) (*sg.SgSgIcmpRule, error) {
	ret := sg.SgSgIcmpRule{
		ICMP: new(common.ICMP),
	}
	ret.Logs = src.Logs
	ret.Trace = src.Trace
	ret.SgFrom = src.SgFrom
	ret.SgTo = src.SgTo
	switch src.Icmp.IPv {
	case model.IPv4:
		ret.ICMP.IPv = common.IpAddrFamily_IPv4
	case model.IPv6:
		ret.ICMP.IPv = common.IpAddrFamily_IPv6
	default:
		return nil, errors.Errorf("got unsupported IPv(%v)", src.Icmp.IPv)
	}
	src.Icmp.Types.Iterate(func(t uint8) bool {
		ret.ICMP.Types = append(ret.ICMP.Types, uint32(t))
		return true
	})
	return &ret, nil
}

func cidrSgRule2proto(src model.CidrSgRule) (*sg.CidrSgRule, error) {
	ret := &sg.CidrSgRule{
		Logs:  src.Logs,
		Trace: src.Trace,
		SG:    src.ID.SG,
		CIDR:  src.ID.CIDR.String(),
	}
	var e error
	if ret.Traffic, e = traffic2proto(src.ID.Traffic); e != nil {
		return nil, e
	}
	if ret.Transport, e = netTranport2proto(src.ID.Transport); e != nil {
		return nil, e
	}
	if ret.Ports, e = sgAccPorts2proto(src.Ports); e != nil {
		return nil, e
	}
	return ret, nil
}

func (srv *sgService) GetRules(ctx context.Context, req *sg.GetRulesReq) (resp *sg.RulesResp, err error) {
	defer func() {
		err = correctError(err)
	}()
	var reader registry.Reader
	if reader, err = srv.registryReader(ctx); err != nil {
		return nil, err
	}
	defer reader.Close() //lint:nolint
	resp = new(sg.RulesResp)
	err = reader.ListSGRules(ctx, func(rule model.SGRule) error {
		r, e := sgRule2proto(rule)
		if e != nil {
			return errors.WithMessagef(e, "on convert SGRule '%s' to proto", rule.ID)
		}
		resp.Rules = append(resp.Rules, r)
		return nil
	}, registry.And(
		registry.SGFrom(req.GetSgFrom()), registry.SGTo(req.GetSgTo()),
	))
	if err != nil {
		return nil,
			status.Errorf(codes.Internal, "reason: %v", err)
	}
	if len(resp.GetRules()) == 0 {
		return nil,
			status.Errorf(codes.NotFound, "not found rules for from SG '%s' to SG '%s'",
				req.GetSgFrom(), req.GetSgTo())
	}
	return resp, nil
}
