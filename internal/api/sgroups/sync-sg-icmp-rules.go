package sgroups

import (
	"math"

	model "github.com/H-BF/sgroups/internal/models/sgroups"
	registry "github.com/H-BF/sgroups/internal/registry/sgroups"
	"github.com/pkg/errors"

	"github.com/H-BF/protos/pkg/api/common"
	sg "github.com/H-BF/protos/pkg/api/sgroups"
)

type prtoto2SgIcmpRule struct {
	*model.SgIcmpRule
}

func (r prtoto2SgIcmpRule) from(src *sg.SgIcmpRule) error {
	r.Sg = src.GetSg()
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
	return nil
}

var syncSgIcmpRule = syncAlg[model.SgIcmpRule, *sg.SgIcmpRule]{
	makePrimaryKeyScope: func(r []model.SgIcmpRule) registry.Scope {
		return registry.PKScopeOfSgIcmpRules(r...)
	},
	proto2model: func(r *sg.SgIcmpRule) (model.SgIcmpRule, error) {
		var ret model.SgIcmpRule
		err := prtoto2SgIcmpRule{&ret}.from(r)
		return ret, err
	},
}.process
