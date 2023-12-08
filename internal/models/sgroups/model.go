package sgroups

import (
	"bytes"
	"crypto/md5" //nolint:gosec
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/H-BF/sgroups/internal/dict"

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

	// Traffic packet traffic any of [INGRESS, EGRESS]
	Traffic uint8

	// ChainDefaultAction default action for SG {DROP|ACCEPT}
	ChainDefaultAction uint8

	// NetworkName net nam
	NetworkName = string

	// FQDN -
	FQDN string

	// ICMP an ICMP proto spec
	ICMP struct {
		IPv   uint8             // Use in IP net version 4 or 6
		Types dict.RBSet[uint8] // Use ICMP message types set of [0-254]
	}

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
		Transport NetworkTransport
		SgFrom    string
		SgTo      string
	}

	// FQDNRuleIdentity -
	FQDNRuleIdentity struct {
		Transport NetworkTransport
		SgFrom    string
		FqdnTo    FQDN
	}

	// CidrSgRuleIdenity -
	CidrSgRuleIdenity struct {
		Transport NetworkTransport
		Traffic   Traffic
		SG        string
		CIDR      net.IPNet
	}

	// SGRulePorts source and destination port ranges
	SGRulePorts struct {
		S PortRanges
		D PortRanges
	}

	// SGRule security rule for From-To security groups
	SGRule = ruleT[SGRuleIdentity]

	// FQDNRule  security rule for From SG to FQDN
	FQDNRule = ruleT[FQDNRuleIdentity]

	// CidrSgRule proto:CIDR:SG:[INGRESS|EGRESS] rule
	CidrSgRule = ruleT[CidrSgRuleIdenity]

	// SyncStatus succeeded sync-op status
	SyncStatus struct {
		UpdatedAt time.Time
	}

	ruleT[T any] struct {
		ID    T
		Ports []SGRulePorts
		Logs  bool
		Trace bool
	}

	ruleID[T any] interface {
		Validate() error
		IsEq(T) bool
		IdentityHash() string
		String() string
	}

	// SgIcmpRule SG:ICMP default rule
	SgIcmpRule struct {
		Sg    string
		Icmp  ICMP
		Logs  bool
		Trace bool
	}

	// SgIcmpRuleID SG:ICMP rule ID
	SgIcmpRuleID struct {
		IPv uint8
		Sg  string
	}

	// SgSgIcmpRule SG-SG:ICMP default rule
	SgSgIcmpRule struct {
		SgFrom string
		SgTo   string
		Icmp   ICMP
		Logs   bool
		Trace  bool
	}

	// SgSgIcmpRuleID SG-SG:ICMP rule ID
	SgSgIcmpRuleID struct {
		IPv    uint8
		SgFrom string
		SgTo   string
	}
)

var (
	_ ruleID[SGRuleIdentity]    = (*SGRuleIdentity)(nil)
	_ ruleID[FQDNRuleIdentity]  = (*FQDNRuleIdentity)(nil)
	_ ruleID[CidrSgRuleIdenity] = (*CidrSgRuleIdenity)(nil)
)

// PortRangeFactory ...
var PortRangeFactory = ranges.IntsFactory(PortNumber(0))

// PortRangeFull port range [0, 65535]
var PortRangeFull = PortRangeFactory.Range(0, false, ^PortNumber(0), false)

const (
	// IPv4 IP family v4
	IPv4 = 4
	// IPv6 IP family v6
	IPv6 = 6
)

const (
	// TCP ...
	TCP NetworkTransport = iota

	// UDP ...
	UDP
)

const (
	// INGRESS as is
	INGRESS Traffic = iota + 1

	// EGRESS as is
	EGRESS
)

const (
	// DEFAULT is mean default action
	DEFAULT ChainDefaultAction = iota

	// DROP drop action net packet
	DROP

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

// String -
func (tfc Traffic) String() string {
	switch tfc {
	case INGRESS:
		return "ingress"
	case EGRESS:
		return "egress"
	}
	return fmt.Sprintf("Undef(%v)", int(tfc))
}

// String impl Stringer
func (a ChainDefaultAction) String() string {
	return [...]string{"default", "drop", "accept"}[a]
}

// FromString inits from string
func (a *ChainDefaultAction) FromString(s string) error {
	const api = "ChainDefaultAction/FromString"
	switch strings.ToLower(s) {
	case "defuault":
		*a = DEFAULT
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

// FromString init from string
func (tfc *Traffic) FromString(s string) error {
	const api = "Traffic/FromString"
	switch strings.ToLower(s) {
	case "ingress":
		*tfc = INGRESS
	case "egress":
		*tfc = EGRESS
	default:
		return errors.WithMessage(fmt.Errorf("unknown value '%s'", s), api)
	}
	return nil
}

// IsEq -
func (nw Network) IsEq(other Network) bool {
	return nw.Name == other.Name &&
		nw.Net.IP.Equal(other.Net.IP) &&
		bytes.Equal(nw.Net.Mask, other.Net.Mask)
}

// IsEq -
func (sg SecurityGroup) IsEq(other SecurityGroup) bool {
	eq := sg.DefaultAction == other.DefaultAction &&
		sg.Logs == other.Logs &&
		sg.Trace == other.Trace
	if eq {
		var a, b dict.HSet[string]
		a.PutMany(sg.Networks...)
		b.PutMany(other.Networks...)
		eq = a.Eq(&b)
	}
	return eq
}

// IdentityHash makes ID as hash for SGRule
func (sgRuleKey SGRuleIdentity) IdentityHash() string {
	hasher := md5.New() //nolint:gosec
	hasher.Write([]byte(sgRuleKey.SgFrom))
	hasher.Write([]byte(sgRuleKey.SgTo))
	hasher.Write([]byte(sgRuleKey.Transport.String()))
	return strings.ToLower(hex.EncodeToString(hasher.Sum(nil)))
}

// IdentityHash makes ID as hash for FQDNRuleIdentity
func (sgRuleKey FQDNRuleIdentity) IdentityHash() string {
	hasher := md5.New() //nolint:gosec
	hasher.Write([]byte(sgRuleKey.SgFrom))
	hasher.Write(bytes.ToLower([]byte(sgRuleKey.FqdnTo)))
	hasher.Write([]byte(sgRuleKey.Transport.String()))
	return strings.ToLower(hex.EncodeToString(hasher.Sum(nil)))
}

// IsEq -
func (sgRuleKey SGRuleIdentity) IsEq(other SGRuleIdentity) bool {
	return sgRuleKey.SgFrom == other.SgFrom &&
		sgRuleKey.SgTo == other.SgTo &&
		sgRuleKey.Transport == other.Transport
}

// IsEq -
func (sgRuleKey FQDNRuleIdentity) IsEq(other FQDNRuleIdentity) bool {
	return sgRuleKey.SgFrom == other.SgFrom &&
		sgRuleKey.FqdnTo.IsEq(other.FqdnTo) &&
		sgRuleKey.Transport == other.Transport
}

// String impl Stringer
func (sgRuleKey SGRuleIdentity) String() string {
	return fmt.Sprintf("%s:sg(%s)sg(%s)",
		sgRuleKey.Transport, sgRuleKey.SgFrom, sgRuleKey.SgTo)
}

// String impl Stringer
func (sgRuleKey FQDNRuleIdentity) String() string {
	return fmt.Sprintf("%s:sg(%s)fqdn(%s)", sgRuleKey.Transport,
		sgRuleKey.SgFrom,
		strings.ToLower(sgRuleKey.FqdnTo.String()))
}

// IsEq -
func (rule ruleT[T]) IsEq(other ruleT[T]) bool {
	return any(rule.ID).(ruleID[T]).IsEq(other.ID) &&
		AreRulePortsEq(rule.Ports, other.Ports) &&
		rule.Logs == other.Logs &&
		rule.Trace == other.Trace
}

// String impl Stringer
func (o FQDN) String() string {
	return string(o)
}

// IsEq chacke if is Eq with no case
func (o FQDN) IsEq(other FQDN) bool {
	return strings.EqualFold(string(o), string(other))
}

// Cmp compare no case
func (o FQDN) Cmp(other FQDN) int {
	if strings.EqualFold(string(o), string(other)) {
		return 0
	}
	if o < other {
		return -1
	}
	return 1
}

// IdentityHash -
func (o SgIcmpRuleID) IdentityHash() string {
	return o.String()
}

// String -
func (o SgIcmpRuleID) String() string {
	return fmt.Sprintf("sg(%s)icmp%v", o.Sg, o.IPv)
}

// IsEq -
func (o SgIcmpRule) IsEq(other SgIcmpRule) bool {
	return o.Logs == other.Logs &&
		o.Trace == other.Trace &&
		o.Sg == other.Sg &&
		o.Icmp.IPv == other.Icmp.IPv &&
		o.Icmp.Types.Eq(&o.Icmp.Types)
}

// ID -
func (o SgIcmpRule) ID() SgIcmpRuleID {
	return SgIcmpRuleID{
		Sg:  o.Sg,
		IPv: o.Icmp.IPv,
	}
}

// IsEq -
func (o SgSgIcmpRule) IsEq(other SgSgIcmpRule) bool {
	return o.Logs == other.Logs &&
		o.Trace == other.Trace &&
		o.SgFrom == other.SgFrom &&
		o.Icmp.IPv == other.Icmp.IPv &&
		o.Icmp.Types.Eq(&o.Icmp.Types)
}

// ID -
func (o SgSgIcmpRule) ID() SgSgIcmpRuleID {
	return SgSgIcmpRuleID{
		SgFrom: o.SgFrom,
		SgTo:   o.SgTo,
		IPv:    o.Icmp.IPv,
	}
}

// IdentityHash -
func (o SgSgIcmpRuleID) IdentityHash() string {
	return o.String()
}

// String -
func (o SgSgIcmpRuleID) String() string {
	return fmt.Sprintf("sg(%s)sg(%s)icmp%v", o.SgFrom, o.SgTo, o.IPv)
}

// String -
func (o CidrSgRuleIdenity) String() string {
	return fmt.Sprintf("%s:cidr(%s)sg(%s)%s",
		o.Transport, &o.CIDR, o.SG, o.Traffic)
}

// IdentityHash -
func (o CidrSgRuleIdenity) IdentityHash() string {
	return o.String()
}

// Cmp -
func (o CidrSgRuleIdenity) Cmp(other CidrSgRuleIdenity) int {
	l, r := o.String(), other.String()
	if l == r {
		return 0
	}
	if l < r {
		return -1
	}
	return 1
}

// IsEq -
func (o CidrSgRuleIdenity) IsEq(other CidrSgRuleIdenity) bool {
	return o.String() == other.String()
}
