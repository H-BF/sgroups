package sgroups

import (
	"net"
	"testing"

	model "github.com/H-BF/sgroups/internal/models/sgroups"
)

//nolint
func Test_1(t *testing.T) {

	var ips scopedIPs
	ips.IPs = append(ips.IPs, net.ParseIP("127.0.0.1"))
	sco := And(Not(Not(ips)), NoScope)
	//sco := Or(Not(Not(scopedIPs{})), noScope{})
	//sco := Not(Not(scopedIPs{}))
	_, n, _ := net.ParseCIDR("127.0.0.0/24")
	nw := model.Network{
		Net: *n,
	}

	var fi filterTree[model.Network]
	if fi.init(sco) {
		ok := fi.invoke(nw)
		if ok {
			i := 1
			i++
		}
	}
}
