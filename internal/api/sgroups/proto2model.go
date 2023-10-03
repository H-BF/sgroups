package sgroups

import (
	model "github.com/H-BF/sgroups/internal/models/sgroups"

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
func Proto2ModelSGRuleIdentity(src *sg.Rule) (model.SGRuleIdentity, error) {
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
func Proto2ModelSGRule(src *sg.Rule) (model.SGRule, error) {
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

/*//
// Proto2ModelPortRanges -
func Proto2ModelPortRanges(src []*sg.AccPorts) ([]model.SGRulePorts, error) {
	var ret rulePorts
	err := ret.from(src)
	return []model.SGRulePorts(ret), err
}
*/
