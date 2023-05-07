package sgroups

import (
	"github.com/H-BF/corlib/pkg/ranges"
	oz "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/pkg/errors"
)

// ErrSPortsAreOverlapped -
var ErrSPortsAreOverlapped = errors.New("source ports have overlapped regions")

type arraySGRulePorts []SGRulePorts

// Validatable is a alias to oz.Validatable
type Validatable = oz.Validatable

// Network validate network model
func (nw Network) Validate() error {
	return oz.ValidateStruct(&nw,
		oz.Field(&nw.Name, oz.Required.Error("network name is required")),
		oz.Field(&nw.Net, oz.By(func(_ interface{}) error {
			n := len(nw.Net.IP)
			n1 := len(nw.Net.Mask)
			if n <= 16 && n <= n1 {
				return nil
			}
			return errors.New("invalid network")
		})),
	)
}

// SecurityGroup security grpoup validate
func (sg SecurityGroup) Validate() error {
	a := make(map[NetworkName]int)
	return oz.ValidateStruct(&sg,
		oz.Field(&sg.Name, oz.Required.Error("security grpoup name is rquired")),
		oz.Field(&sg.Networks,
			oz.Each(oz.By(func(value interface{}) error {
				nw := value.(string)
				if e := oz.Validate(nw, oz.Required.Error("network name is required")); e != nil {
					return e
				}
				if a[nw]++; a[nw] > 1 {
					return errors.Errorf("network '%s' referenced more tna once", nw)
				}
				return nil
			})),
		),
	)
}

// Validate net transport validator
func (nt NetworkTransport) Validate() error {
	return oz.Validate(nt, oz.In(TCP, UDP).Error("must be in ['TCP', 'UDP']"), oz.Skip)
}

// Validate validate of SGRuleIdentity
func (sgRuleKey SGRuleIdentity) Validate() error {
	vali := func(value any) error {
		sg := value.(SecurityGroup)
		return oz.Validate(sg.Name, oz.Required.Error("sg name is required"))
	}
	return oz.ValidateStruct(&sgRuleKey,
		oz.Field(&sgRuleKey.Transport),
		oz.Field(&sgRuleKey.SgFrom, oz.By(vali), oz.Skip),
		oz.Field(&sgRuleKey.SgTo, oz.By(vali), oz.Skip),
	)
}

// Validate -
func (ports SGRulePorts) Validate() error {
	return oz.ValidateStruct(&ports,
		oz.Field(&ports.D, oz.Required.When(ports.S == nil || ports.S.IsNull()).
			Error("D ports are required when S ports are not provided")),
		oz.Field(&ports.S, oz.Required.When(ports.D == nil || ports.D.IsNull()).
			Error("S ports are required when D ports are not provided")),
	)
}

// Validate validates security group rule
func (rule SGRule) Validate() error {
	return oz.ValidateStruct(&rule,
		oz.Field(&rule.SGRuleIdentity),
		oz.Field(&rule.Ports,
			//oz.Required.Error("ports are required"),
			oz.By(func(_ any) error {
				return arraySGRulePorts(rule.Ports).Validate()
			}),
			oz.Skip,
		),
	)
}

func (a arraySGRulePorts) Validate() error {
	rr := make([]PortRange, 0, len(a))
	e := oz.Validate([]SGRulePorts(a),
		oz.Each(oz.By(func(value any) error {
			if p := value.(SGRulePorts); p.S == nil {
				rr = append(rr, PortRangeFull)
			} else {
				rr = append(rr, p.S)
			}
			return nil
		})),
		oz.Skip,
	)
	if e == nil {
		x := ranges.NewMultiRange(PortRangeFactory)
		x.Update(ranges.CombineMerge, rr...)
		if len(rr) != x.Len() {
			e = ErrSPortsAreOverlapped
		}
	}
	return e
}
