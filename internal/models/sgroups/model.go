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

	// ChainDefaultAction default action for SG {DROP|ACCEPT}
	ChainDefaultAction uint8

	// NetworkName net nam
	NetworkName = string

	// Network is IP network
	Network struct {
		Net  net.IPNet
		Name NetworkName
	}

	// SecurityGroup security group for networks(s)
	SecurityGroup struct {
		Name          string
		Networks      []NetworkName
		Logs          bool
		Trace         bool
		DefaultAction ChainDefaultAction
	}

	// SGRuleIdentity security rule ID as key
	SGRuleIdentity struct {
		SgFrom    SecurityGroup
		SgTo      SecurityGroup
		Transport NetworkTransport
	}

	// SGRulePorts source and destination port ranges
	SGRulePorts struct {
		S PortRanges
		D PortRanges
	}

	// SGRule security rule for From-To security groups
	SGRule struct {
		SGRuleIdentity
		Ports []SGRulePorts
		Logs  bool
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

const (
	// DROP drop action net packet
	DROP ChainDefaultAction = iota

	// ACCEPT accept action net packet
	ACCEPT
)

// NewPortRarnges is a port rarnges constructor
func NewPortRarnges() PortRanges {
	return ranges.NewMultiRange(PortRangeFactory)
}

// String impl Stringer
func (nw Network) String() string {
	return fmt.Sprintf("%s(%s)", nw.Name, &nw.Net)
}

// String impl Stringer
func (nt NetworkTransport) String() string {
	return [...]string{"tcp", "udp"}[nt]
}

// String impl Stringer
func (a ChainDefaultAction) String() string {
	return [...]string{"drop", "accept"}[a]
}

// FromString inits from string
func (a *ChainDefaultAction) FromString(s string) error {
	const api = "ChainDefaultAction/FromString"
	switch strings.ToLower(s) {
	case "drop":
		*a = DROP
	case "accept":
		*a = ACCEPT
	default:
		return errors.WithMessage(fmt.Errorf("unknown value '%s'", s), api)
	}
	return nil
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

// IsEq -
func (sgRuleKey SGRuleIdentity) IsEq(other SGRuleIdentity) bool {
	return sgRuleKey.SgFrom.Name == other.SgFrom.Name &&
		sgRuleKey.SgTo.Name == other.SgTo.Name &&
		sgRuleKey.Transport == other.Transport
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
	return rule.SGRuleIdentity.IsEq(other.SGRuleIdentity) &&
		AreRulePortsEq(rule.Ports, other.Ports) &&
		rule.Logs == other.Logs
}
