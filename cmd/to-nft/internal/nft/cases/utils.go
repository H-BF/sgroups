package cases

import (
	"net"
)

// SeparateNetworks it selerates source into IPv4 and IPv4 networks
func SeparateNetworks(nws []Network, scopeIPs ...net.IP) (netIPv4, netIPv6 []Network) {
	_ = scopeIPs
	netIPv4, netIPv6 = make([]Network, 0, len(nws)),
		make([]Network, 0, len(nws))

	for _, nw := range nws {
		if doInc := false; len(scopeIPs) > 0 {
			for i := range scopeIPs {
				if doInc = nw.Net.Contains(scopeIPs[i]); doInc {
					break
				}
			}
			if !doInc {
				continue
			}
		}
		switch len(nw.Net.IP) {
		case net.IPv6len:
			netIPv6 = append(netIPv6, nw)
		case net.IPv4len:
			netIPv4 = append(netIPv4, nw)
		}
	}
	return netIPv4, netIPv6
}
