package sgroups

import (
	"net"
	"regexp"
	"unsafe"

	"github.com/H-BF/corlib/pkg/ranges"
	"github.com/H-BF/sgroups/internal/dict"
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

	// ErrInvalidFQDN -
	ErrInvalidFQDN = errors.New("invalid FQDN")
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
	a := make(map[NetworkName]int)
	return oz.ValidateStruct(&sg,
		oz.Field(&sg.Name, oz.Required.Error(sgNameRequired), oz.Match(reCName)),
		oz.Field(&sg.DefaultAction),
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

// Validate ChainDefaultAction validator
func (a ChainDefaultAction) Validate() error {
	vals, x := [...]any{int(DEFAULT), int(DROP), int(ACCEPT)}, int(a)
	return oz.Validate(x, oz.In(vals[:]...).Error("must be in ['DROP', 'ACCEPT']"))
}

// Validate net transport validator
func (nt NetworkTransport) Validate() error {
	vals, x := [...]any{int(TCP), int(UDP)}, int(nt)
	return oz.Validate(x, oz.In(vals[:]...).Error("must be in ['TCP', 'UDP']"))
}

// Validate net transport validator
func (tfc Traffic) Validate() error {
	vals, x := [...]any{int(INGRESS), int(EGRESS)}, int(tfc)
	return oz.Validate(x, oz.In(vals[:]...).Error("must be in ['INGRESS', 'EGRESS']"))
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
	)
}

// Validate impl Validator
func (o FQDN) Validate() error {
	a := unsafe.Slice(
		unsafe.StringData(string(o)), len(o),
	)
	if m := reFQDN.Match(a); !m || len(a) > 255 {
		return ErrInvalidFQDN
	}
	return nil
}

// Validate impl Validator
func (o ICMP) Validate() error {
	return oz.ValidateStruct(&o,
		oz.Field(&o.IPv, oz.Required, oz.In(uint8(IPv4), uint8(IPv6)).
			Error("IPv should be in [4,6]")),
	)
}

// Validate impl Validator
func (o SgIcmpRule) Validate() error {
	return oz.ValidateStruct(&o,
		oz.Field(&o.Sg, oz.Required.Error(sgNameRequired),
			oz.Match(reCName)),
		oz.Field(&o.Icmp),
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
	)
}

// Validate impl Validator
func (o IESgSgIcmpRule) Validate() error {
	return oz.ValidateStruct(&o,
		oz.Field(&o.Traffic),
		oz.Field(&o.SgLocal, oz.Required.Error(sgNameRequired), oz.Match(reCName)),
		oz.Field(&o.Sg, oz.Required.Error(sgNameRequired), oz.Match(reCName)),
		oz.Field(&o.Icmp),
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

func (o CidrSgIcmpRule) Validate() error {
	return oz.ValidateStruct(&o,
		oz.Field(&o.Traffic),
		oz.Field(&o.CIDR, oz.By(cidrIsValid)),
		oz.Field(&o.SG, oz.Required.Error(sgNameRequired), oz.Match(reCName)),
		oz.Field(&o.Icmp),
	)
}

// Validate validate of CidrSgRuleIdenity
func (o CidrSgRuleIdenity) Validate() error {
	return oz.ValidateStruct(&o,
		oz.Field(&o.Transport),
		oz.Field(&o.Traffic),
		oz.Field(&o.SG, oz.Required.Error(sgNameRequired), oz.Match(reCName)),
		oz.Field(&o.CIDR, oz.By(cidrIsValid)),
	)
}

// Validate implements ruleID.
func (o SgSgRuleIdentity) Validate() error {
	return oz.ValidateStruct(&o,
		oz.Field(&o.Transport),
		oz.Field(&o.Traffic),
		oz.Field(&o.SgLocal, oz.Required.Error(sgNameRequired), oz.Match(reCName)),
		oz.Field(&o.Sg, oz.Required.Error(sgNameRequired), oz.Match(reCName)))
}

// Validate validate of FQDNRule
func (o FQDNRule) Validate() error {
	return oz.ValidateStruct(&o,
		oz.Field(&o.ruleT),
		oz.Field(&o.NdpiProtocols, oz.By(func(_ any) error {
			const lim = 255
			if n := o.NdpiProtocols.Len(); n > lim {
				return errors.Errorf("protocols count is %v but it must be <= %v", n, lim)
			}
			var e error
			o.NdpiProtocols.Iterate(func(k dict.StringCiKey) bool {
				if len(k) == 0 || !reCName.MatchString(string(k)) {
					e = errors.Errorf("bad protocol name '%v'", k)
				}
				return e == nil
			})
			return nil
		})))
}

var (
	reCName = regexp.MustCompile(`^\S(.*\S)?$`)

	reFQDN = regexp.MustCompile(`(?ims)^([a-z0-9\*][a-z0-9_-]{1,62}){1}(\.[a-z0-9_][a-z0-9_-]{0,62})*$`)
)
