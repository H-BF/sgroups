package resources

import (
	"net"
	"reflect"

	model "github.com/H-BF/sgroups/internal/domains/sgroups"

	"github.com/H-BF/corlib/pkg/dict"
	"github.com/ahmetb/go-linq/v3"
)

// SeparateNetworks it selerates source into IPv4 and IPv4 networks
func SeparateNetworks(nws []Network, scopeIPs ...net.IP) (netIPv4, netIPv6 []net.IPNet) {
	netIPv4, netIPv6 = make([]net.IPNet, 0, len(nws)),
		make([]net.IPNet, 0, len(nws))

	pass := func(nw Network) bool {
		for i := range scopeIPs {
			if nw.Net.Contains(scopeIPs[i]) {
				return true
			}
		}
		return len(scopeIPs) == 0
	}
	linq.From(nws).
		Where(func(i any) bool {
			return pass(i.(Network))
		}).
		ForEach(func(i any) {
			nw := i.(Network)
			switch len(nw.Net.IP) {
			case net.IPv6len:
				netIPv6 = append(netIPv6, nw.Net)
			case net.IPv4len:
				netIPv4 = append(netIPv4, nw.Net)
			}
		})
	return netIPv4, netIPv6
}

type ruleTypeKind interface {
	model.SGRule | *model.SGRule |
		model.FQDNRule | *model.FQDNRule |
		model.SgSgIcmpRule | *model.SgSgIcmpRule |
		model.IECidrSgRule | *model.IECidrSgRule |
		model.IESgSgRule | *model.IESgSgRule |
		model.IESgSgIcmpRule | *model.IESgSgIcmpRule |
		model.IECidrSgIcmpRule | *model.IECidrSgIcmpRule
}

// RuleBasePriority -
func RuleBasePriority[ruleT ruleTypeKind](_ ruleT) int16 {
	v := ruleBasePriorities.At(
		reflect.TypeOf((*ruleT)(nil)).Elem(),
	)
	return *v
}

func regRuleBasePriority[ruleT ruleTypeKind](basePri int16) {
	ruleBasePriorities.Put(reflect.TypeOf((*ruleT)(nil)).Elem(), &basePri)
}

var ruleBasePriorities dict.HDict[reflect.Type, *int16]

//nolint:mnd
func init() {
	regRuleBasePriority[model.SgSgIcmpRule](-300)
	regRuleBasePriority[*model.SgSgIcmpRule](-300)

	regRuleBasePriority[model.SGRule](-200)
	regRuleBasePriority[*model.SGRule](-200)

	regRuleBasePriority[model.IESgSgIcmpRule](-100)
	regRuleBasePriority[*model.IESgSgIcmpRule](-100)

	regRuleBasePriority[model.IESgSgRule](0)
	regRuleBasePriority[*model.IESgSgRule](0)

	regRuleBasePriority[model.FQDNRule](100)
	regRuleBasePriority[*model.FQDNRule](100)

	regRuleBasePriority[model.IECidrSgIcmpRule](200)
	regRuleBasePriority[*model.IECidrSgIcmpRule](200)

	regRuleBasePriority[model.IECidrSgRule](300)
	regRuleBasePriority[*model.IECidrSgRule](300)
}
