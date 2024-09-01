package sgroups

import (
	"net"
	"regexp"

	"github.com/H-BF/corlib/pkg/ranges"
	oz "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/pkg/errors"
)

const (
	sgNameRequired = "security group name is required"
)

var (
	// ErrSPortsAreOverlapped -
	ErrSPortsAreOverlapped = errors.New("source ports have overlapped regions")

	// ErrUnexpectedNullPortRange -
	ErrUnexpectedNullPortRange = errors.New("unexpected null port range")

	errICMPrequiresNetIPv4  = errors.New("ICMP requires IPv4 net")
	errICMP6requiresNetIPv6 = errors.New("ICMP6 requires IPv6 net")
)

// Validatable is a alias to oz.Validatable
type Validatable = oz.Validatable

// Validate network model validate
func (nw Network) Validate() error {
	return oz.ValidateStruct(&nw,
		oz.Field(&nw.Name, oz.Required.Error("network name is required"), oz.Match(reCName)),
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

// Validate security grpoup model validate
func (sg SecurityGroup) Validate() error {
	return oz.ValidateStruct(&sg,
		oz.Field(&sg.Name, oz.Required.Error(sgNameRequired), oz.Match(reCName)),
		oz.Field(&sg.DefaultAction),
		oz.Field(&sg.Networks,
			oz.By(func(_ any) error {
				var e error
				sg.Networks.Iterate(func(k NetworkName) bool {
					if len(k) == 0 {
						e = errors.New("network name cannot be empty")
					}
					return e == nil
				})
				return e
			}),
		),
	)
}

// Validate validate of SGRuleIdentity
func (sgRuleKey SGRuleIdentity) Validate() error {
	return oz.ValidateStruct(&sgRuleKey,
		oz.Field(&sgRuleKey.Transport),
		oz.Field(&sgRuleKey.SgFrom, oz.Required.Error(sgNameRequired), oz.Match(reCName)),
		oz.Field(&sgRuleKey.SgTo, oz.Required.Error(sgNameRequired), oz.Match(reCName)),
	)
}

// Validate validate of FQDNRuleIdentity
func (o FQDNRuleIdentity) Validate() error {
	return oz.ValidateStruct(&o,
		oz.Field(&o.Transport),
		oz.Field(&o.SgFrom, oz.Required.Error(sgNameRequired), oz.Match(reCName)),
		oz.Field(&o.FqdnTo),
	)
}

// ValidatePortRange portrange model validate
func ValidatePortRange(pr PortRange, canBeNull bool) error {
	if pr.IsNull() && !canBeNull {
		return ErrUnexpectedNullPortRange
	}
	return nil
}

// Validate SGRulePorts model validate
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

// Validate validates security rule
func (rule ruleT[T]) Validate() error {
	return oz.ValidateStruct(&rule,
		oz.Field(&rule.ID),
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
		oz.Field(&rule.Action),
	)
}

// Validate impl Validator
func (o SgIcmpRule) Validate() error {
	return oz.ValidateStruct(&o,
		oz.Field(&o.Sg, oz.Required.Error(sgNameRequired),
			oz.Match(reCName)),
		oz.Field(&o.Icmp),
		oz.Field(&o.Action),
	)
}

// Validate impl Validator
func (o SgSgIcmpRule) Validate() error {
	return oz.ValidateStruct(&o,
		oz.Field(&o.SgFrom, oz.Required.Error(sgNameRequired),
			oz.Match(reCName)),
		oz.Field(&o.SgTo, oz.Required.Error(sgNameRequired),
			oz.Match(reCName)),
		oz.Field(&o.Icmp),
		oz.Field(&o.Action),
	)
}

// Validate impl Validator
func (o IESgSgIcmpRule) Validate() error {
	return oz.ValidateStruct(&o,
		oz.Field(&o.Traffic),
		oz.Field(&o.SgLocal, oz.Required.Error(sgNameRequired), oz.Match(reCName)),
		oz.Field(&o.Sg, oz.Required.Error(sgNameRequired), oz.Match(reCName)),
		oz.Field(&o.Icmp),
		oz.Field(&o.Action),
	)
}

func cidrIsValid(v interface{}) error {
	cidr, _ := v.(net.IPNet)
	switch len(cidr.IP) {
	case net.IPv4len, net.IPv6len:
	default:
		return errors.New("IP of net is invalid")
	}
	if len(cidr.Mask) != len(cidr.IP) {
		return errors.New("net mask is invalid")
	}
	return nil
}

func (o IECidrSgIcmpRule) Validate() error {
	return oz.ValidateStruct(&o,
		oz.Field(&o.Traffic),
		oz.Field(&o.Icmp),
		oz.Field(&o.CIDR, oz.By(func(_ any) (e error) {
			defer func() {
				e = errors.WithMessagef(e, "bad value '%s'", &o.CIDR)
			}()
			if e = cidrIsValid(o.CIDR); e != nil {
				return e
			}
			switch n := len(o.CIDR.IP); o.Icmp.IPv {
			case IPv4:
				if n != net.IPv4len {
					e = errICMPrequiresNetIPv4
				}
			case IPv6:
				if n != net.IPv6len {
					e = errICMP6requiresNetIPv6
				}
			default:
				panic("IECidrSgIcmpRule.Validate UB")
			}
			return e
		})),
		oz.Field(&o.SG, oz.Required.Error(sgNameRequired), oz.Match(reCName)),
		oz.Field(&o.Action),
	)
}

// Validate validate of CidrSgRuleIdenity
func (o IECidrSgRuleIdenity) Validate() error {
	return oz.ValidateStruct(&o,
		oz.Field(&o.Transport),
		oz.Field(&o.Traffic),
		oz.Field(&o.SG, oz.Required.Error(sgNameRequired), oz.Match(reCName)),
		oz.Field(&o.CIDR, oz.By(cidrIsValid)),
	)
}

// Validate implements ruleID.
func (o IESgSgRuleIdentity) Validate() error {
	return oz.ValidateStruct(&o,
		oz.Field(&o.Transport),
		oz.Field(&o.Traffic),
		oz.Field(&o.SgLocal, oz.Required.Error(sgNameRequired), oz.Match(reCName)),
		oz.Field(&o.Sg, oz.Required.Error(sgNameRequired), oz.Match(reCName)))
}

var (
	reCName = regexp.MustCompile(`^\S(.*\S)?$`)
)
