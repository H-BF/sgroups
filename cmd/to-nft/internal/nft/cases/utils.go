package cases

import (
	"net"

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
