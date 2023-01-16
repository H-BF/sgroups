package sgroups

import (
	sg "github.com/H-BF/protos/pkg/api/sgroups"
	model "github.com/H-BF/sgroups/internal/models/sgroups"
	"github.com/pkg/errors"
)

// Proto2ModelNetwork converts Network (proto --> model)
func Proto2ModelNetwork(protoNw *sg.Network) (model.Network, error) {
	const api = "proto2model-Network-conv"
	var ret network
	err := ret.from(protoNw)
	return ret.Network, errors.WithMessage(err, api)
}

// Proto2ModelSG conv SG (proto --> model)
func Proto2ModelSG(g *sg.SecGroup) (model.SecurityGroup, error) {
	const api = "proto2model-SG-conv"

	var ret securityGroup
	ret.from(g)
	ret.Networks = ret.Networks[:0]
	for _, nw := range g.GetNetworks() {
		n, e := Proto2ModelNetwork(nw)
		if e != nil {
			return ret.SecurityGroup, errors.WithMessage(e, api)
		}
		ret.Networks = append(ret.Networks, n)
	}
	return ret.SecurityGroup, nil
}

// Proto2ModelSGRule conv SGRule (proto --> model)
func Proto2ModelSGRule(src *sg.Rule) (model.SGRule, error) {
	const api = "proto2model-SGRule-conv"

	var ret model.SGRule
	err := (sgRule{&ret}).from(src)
	if err != nil {
		return ret, errors.WithMessage(err, api)
	}
	if ret.SgFrom, err = Proto2ModelSG(src.GetSgFrom()); err != nil {
		return ret, errors.WithMessage(err, api)
	}
	if ret.SgTo, err = Proto2ModelSG(src.GetSgTo()); err != nil {
		return ret, errors.WithMessage(err, api)
	}
	return ret, nil
}
