package sgroups

import (
	"github.com/H-BF/corlib/pkg/ranges"
	oz "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/pkg/errors"
)

var (
	// ErrSPortsAreOverlapped -
	ErrSPortsAreOverlapped = errors.New("source ports have overlapped regions")

	// ErrUnexpectedNullPortRange -
	ErrUnexpectedNullPortRange = errors.New("unexpected null port range")
)

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

// ValidatePortRange -
func ValidatePortRange(pr PortRange, canBeNull bool) error {
	if pr.IsNull() && !canBeNull {
		return ErrUnexpectedNullPortRange
	}
	return nil
}

// Validate -
func (ports SGRulePorts) Validate() error {
	if ports.S.Len()+ports.D.Len() <= 0 {
		return errors.Errorf("no any 'S' and 'D' port are present")
	}
	var err error
	ports.D.Iterate(func(r PortRange) bool {
		if err = ValidatePortRange(r, false); err != nil {
			err = errors.WithMessagef(err, "on validate 'D' ports(%s) found bad range(%s)", ports.D, r)
		}
		return err == nil
	})
	if err == nil {
		ports.S.Iterate(func(r PortRange) bool {
			if err = ValidatePortRange(r, false); err != nil {
				err = errors.WithMessagef(err, "on validate 'S' ports(%s) found bad range(%s)", ports.S, r)
			}
			return err == nil
		})
	}
	return err
}

// Validate validates security group rule
func (rule SGRule) Validate() error {
	return oz.ValidateStruct(&rule,
		oz.Field(&rule.SGRuleIdentity),
		oz.Field(&rule.Ports,
			//oz.Required.Error("required"),
			oz.By(func(v any) error {
				var rr []PortRange
				for _, p := range v.([]SGRulePorts) {
					if p.S.Len() == 0 {
						rr = append(rr, PortRangeFull)
					} else {
						p.S.Iterate(func(r PortRange) bool {
							rr = append(rr, r)
							return true
						})
					}
				}
				x := NewPortRarnges()
				x.Update(ranges.CombineMerge, rr...)
				if len(rr) != x.Len() {
					return ErrSPortsAreOverlapped
				}
				return nil
			}),
			//oz.Skip,
		),
	)
}
