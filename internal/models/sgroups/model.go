package sgroups

import (
	"crypto/md5" //nolint:gosec
	"encoding/hex"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/H-BF/corlib/pkg/ranges"
	"github.com/pkg/errors"
)

type (
	// PortNumber net port num
	PortNumber = uint16

	// PortRanges net port ranges
	PortRanges = ranges.MultiRange[PortNumber]

	// PortRange net port range
	PortRange = ranges.Range[PortNumber]

	// NetworkTransport net transport
	NetworkTransport uint8

	// NetworkName net nam
	NetworkName = string

	// Network is IP network
	Network struct {
		Net  net.IPNet
		Name NetworkName
	}

	// SecurityGroup security group for networks(s)
	SecurityGroup struct {
		Name     string
		Networks []NetworkName
	}

	// SGRuleIdentity security rule ID as key
	SGRuleIdentity struct {
		SgFrom    SecurityGroup
		SgTo      SecurityGroup
		Transport NetworkTransport
	}

	// SGRulePorts source and destination port ranges
	SGRulePorts struct {
		S PortRange
		D PortRange
	}

	// SGRule security rule for From-To security groups
	SGRule struct {
		SGRuleIdentity
		Ports []SGRulePorts
	}

	// SyncStatus succeeded sync-op status
	SyncStatus struct {
		UpdatedAt time.Time
	}
)

// PortRangeFactory ...
var PortRangeFactory = ranges.IntsFactory(PortNumber(0))

// PortRangeFull port range [0, 65535]
var PortRangeFull = PortRangeFactory.Range(0, false, ^PortNumber(0), false)

var sgRuleIdentityRE = regexp.MustCompile(`^\s*(\w+)\s*:\s*'(` +
	sgNameRePatt +
	`)'\s*-\s*'(` +
	sgNameRePatt + `)'`)

const (
	sgNameRePatt = `[\w\>\<\:\*\.\+\-\@\#\=\~\%\$\/\\]+`
)

const (
	// TCP ...
	TCP NetworkTransport = iota

	// UDP ...
	UDP
)

// String impl Stringer
func (nw Network) String() string {
	return fmt.Sprintf("%s(%s)", nw.Name, &nw.Net)
}

// String impl Stringer
func (nt NetworkTransport) String() string {
	return [...]string{"tcp", "udp"}[nt]
}

// FromString init from string
func (nt *NetworkTransport) FromString(s string) error {
	const api = "NetworkTransport/FromString"
	switch strings.ToLower(s) {
	case "tcp":
		*nt = TCP
	case "udp":
		*nt = UDP
	default:
		return errors.WithMessage(fmt.Errorf("unknown value '%s'", s), api)
	}
	return nil
}

// IdentityHash makes ID as hash for SGRule
func (sgRuleKey SGRuleIdentity) IdentityHash() string {
	hasher := md5.New() //nolint:gosec
	hasher.Write([]byte(sgRuleKey.SgFrom.Name))
	hasher.Write([]byte(sgRuleKey.SgTo.Name))
	hasher.Write([]byte(sgRuleKey.Transport.String()))
	return strings.ToLower(hex.EncodeToString(hasher.Sum(nil)))
}

// String impl Stringer
func (sgRuleKey SGRuleIdentity) String() string {
	return fmt.Sprintf("%s:'%s'-'%s'",
		sgRuleKey.Transport, sgRuleKey.SgFrom.Name, sgRuleKey.SgTo.Name)
}

// FromString init from string
func (sgRuleKey *SGRuleIdentity) FromString(s string) error {
	const api = "SGRuleIdentity/FromString"
	r := sgRuleIdentityRE.FindStringSubmatch(s)
	if len(r) != 4 { //nolint:gomnd
		return errors.Errorf("%s: bad source(%s)", api, s)
	}
	if err := sgRuleKey.Transport.FromString(r[1]); err != nil {
		return errors.WithMessage(err, api)
	}
	sgRuleKey.SgFrom.Name = r[2]
	sgRuleKey.SgTo.Name = r[3]
	return nil
}

// IsEq -
func (rule SGRule) IsEq(other SGRule) bool {
	return rule.IdentityHash() == other.IdentityHash() &&
		AreRulePortsEq(rule.Ports, other.Ports)
}

// ArePortsValid -
func (rule SGRule) ArePortsValid() bool {
	rr := make([]PortRange, 0, len(rule.Ports))
	for _, p := range rule.Ports {
		if p.S == nil {
			return len(rule.Ports) == 1
		}
		rr = append(rr, p.S)
	}
	x := ranges.NewMultiRange(PortRangeFactory)
	x.Update(ranges.CombineMerge, rr...)
	return len(rr) == x.Len()
}
