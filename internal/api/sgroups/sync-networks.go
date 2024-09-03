package sgroups

import (
	"net"

	model "github.com/H-BF/sgroups/v2/internal/domains/sgroups"
	registry "github.com/H-BF/sgroups/v2/internal/registry/sgroups"

	sg "github.com/H-BF/protos/pkg/api/sgroups"
	"github.com/pkg/errors"
)

type network struct {
	model.Network
}

func (n *network) from(protoNw *sg.Network) error {
	n.Name = protoNw.GetName()
	c := protoNw.GetNetwork().GetCIDR()
	ip, nt, err := net.ParseCIDR(c)
	if err != nil {
		return err
	}
	if !nt.IP.Equal(ip) {
		return errors.Errorf("the '%s' seems just an IP address; the address of network is expected instead", c)
	}
	n.Net = *nt
	return nil
}

var syncNetworks = syncAlg[model.Network, *sg.Network]{
	makePrimaryKeyScope: func(nws []model.Network) registry.Scope {
		names := make([]string, 0, len(nws))
		for _, nw := range nws {
			names = append(names, nw.Name)
		}
		return registry.NetworkNames(names...)
	},
	proto2model: func(nw *sg.Network) (model.Network, error) {
		var item network
		err := item.from(nw)
		return item.Network, err
	},
}.process
