package sgroups

import (
	model "github.com/H-BF/sgroups/internal/domains/sgroups"

	sg "github.com/H-BF/protos/pkg/api/sgroups"
	"github.com/pkg/errors"
)

// Proto2ModelNetwork converts Network (proto --> model)
func Proto2ModelNetwork(protoNw *sg.Network) (model.Network, error) {
	const api = "proto2model-Network-conv" //nolint:gosec
	var ret network
	err := ret.from(protoNw)
	return ret.Network, errors.WithMessage(err, api)
}

// Proto2ModelSG conv SG (proto --> model)
func Proto2ModelSG(g *sg.SecGroup) (model.SecurityGroup, error) {
	const api = "proto2model-SG-conv"
	var ret securityGroup
	e := ret.from(g)
	return ret.SecurityGroup, errors.WithMessage(e, api)
}

// Proto2ModelSGRuleIdentity -
func Proto2ModelSGRuleIdentity(src *sg.SgSgRule) (model.SGRuleIdentity, error) {
	const api = "proto2model-SGRuleIdentity-conv"
	var ret model.SGRuleIdentity
	err := (sgRuleIdentity{&ret}).from(src)
	return ret, errors.WithMessage(err, api)
}

// Proto2ModelFQDNRuleIdentity -
func Proto2ModelFQDNRuleIdentity(src *sg.FqdnRule) (model.FQDNRuleIdentity, error) {
	const api = "proto2model-FQDNRuleIdentity-conv"
	var ret model.FQDNRuleIdentity
	err := (sgFqdnRuleIdentity{&ret}).from(src)
	return ret, errors.WithMessage(err, api)
}

// Proto2ModelSGRule conv SGRule (proto --> model)
func Proto2ModelSGRule(src *sg.SgSgRule) (model.SGRule, error) {
	const api = "proto2model-SGRule-conv"
	var ret model.SGRule
	err := sgRule{SGRule: &ret}.from(src)
	return ret, errors.WithMessage(err, api)
}

// Proto2ModelFQDNRule conv FQDNRule (proto --> model)
func Proto2ModelFQDNRule(src *sg.FqdnRule) (model.FQDNRule, error) {
	const api = "proto2model-FQDNRule-conv"
	var ret model.FQDNRule
	err := sgFqdnRule{FQDNRule: &ret}.from(src)
	return ret, errors.WithMessage(err, api)
}

// Proto2MOdelSgIcmpRule conv SgIcmpRule (proto --> model)
func Proto2MOdelSgIcmpRule(src *sg.SgIcmpRule) (model.SgIcmpRule, error) {
	const api = "proto2model-SgIcmpRule-conv"
	var ret model.SgIcmpRule
	err := proto2SgIcmpRule{SgIcmpRule: &ret}.from(src)
	return ret, errors.WithMessage(err, api)
}

// Proto2MOdelSgSgIcmpRule conv SgSgIcmpRule (proto --> model)
func Proto2MOdelSgSgIcmpRule(src *sg.SgSgIcmpRule) (model.SgSgIcmpRule, error) {
	const api = "proto2model-SgSgIcmpRule-conv"
	var ret model.SgSgIcmpRule
	err := proto2SgSgIcmpRule{SgSgIcmpRule: &ret}.from(src)
	return ret, errors.WithMessage(err, api)
}

// Proto2ModelCidrSgRule conv IECidrSgRule (proto --> model)
func Proto2ModelCidrSgRule(src *sg.IECidrSgRule) (model.IECidrSgRule, error) {
	const api = "proto2model-IECidrSgRule-conv"
	var ret model.IECidrSgRule
	err := cidrSgRule{IECidrSgRule: &ret}.from(src)
	return ret, errors.WithMessage(err, api)
}

// Proto2ModelIECidrSgIcmpRule conv CidrSgIcmpRule (proto --> model)
func Proto2ModelIECidrSgIcmpRule(src *sg.IECidrSgIcmpRule) (model.IECidrSgIcmpRule, error) {
	const api = "proto2model-IECidrSgIcmpRule-conv"
	var ret model.IECidrSgIcmpRule
	err := proto2CidrSgIcmpRule{IECidrSgIcmpRule: &ret}.from(src)
	return ret, errors.WithMessage(err, api)
}

// Proto2ModelSgSgRule conv IESgSgRule (proto --> model)
func Proto2ModelSgSgRule(src *sg.IESgSgRule) (ret model.IESgSgRule, err error) {
	const api = "proto2model-IESgSgRule-conv"
	err = sgSgRule{IESgSgRule: &ret}.from(src)
	return ret, errors.WithMessage(err, api)
}

// Proto2ModelIESgSgIcmpRule conv IESgSgIcmpRule (proto --> model)
func Proto2ModelIESgSgIcmpRule(src *sg.IESgSgIcmpRule) (ret model.IESgSgIcmpRule, err error) {
	const api = "proto2model-IESgSgIcmpRule-conv"
	err = proto2IESgSgIcmpRule{IESgSgIcmpRule: &ret}.from(src)
	return ret, errors.WithMessage(err, api)
}
