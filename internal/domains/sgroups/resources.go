package sgroups

import (
	"bytes"
	"crypto/md5" //nolint:gosec
	"encoding/hex"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"

	"github.com/H-BF/corlib/pkg/dict"
	"github.com/H-BF/corlib/pkg/option"
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
		Networks      dict.HSet[NetworkName]
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

	// IECidrSgRuleIdenity -
	IECidrSgRuleIdenity struct {
		Transport NetworkTransport
		Traffic   Traffic
		SG        string
		CIDR      net.IPNet
	}

	// IESgSgRuleIdentity -
	IESgSgRuleIdentity struct {
		Transport NetworkTransport
		Traffic   Traffic
		SgLocal   string
		Sg        string
	}

	// SGRulePorts source and destination port ranges
	SGRulePorts struct {
		S PortRanges
		D PortRanges
	}

	// SGRule security rule for From-To security groups
	SGRule = ruleT[SGRuleIdentity]

	// FQDNRule rule for from SG to FQDN
	FQDNRule = ruleT[FQDNRuleIdentity]

	// IECidrSgRule proto:CIDR:SG:[INGRESS|EGRESS] rule
	IECidrSgRule = ruleT[IECidrSgRuleIdenity]

	// IESgSgRule proto:SG:SG:[INGRESS|EGRESS] rule
	IESgSgRule = ruleT[IESgSgRuleIdentity]

	// SyncStatus succeeded sync-op status
	SyncStatus struct {
		UpdatedAt time.Time
	}

	// RuleAction terminal verdict action for rules
	RuleAction uint8

	// RulePriority represents rule priority i e relative placement pos in the rule list
	RulePriority struct {
		option.ValueOf[int16]
	}

	ruleT[T any] struct {
		ID       T
		Ports    []SGRulePorts
		Logs     bool
		Trace    bool
		Action   RuleAction
		Priority RulePriority
	}

	ruleID[T any] interface {
		Validate() error
		IsEq(T) bool
		IdentityHash() string
		String() string
	}

	// SgIcmpRule SG:ICMP default rule
	SgIcmpRule struct {
		Sg     string
		Icmp   ICMP
		Logs   bool
		Trace  bool
		Action RuleAction
	}

	// SgIcmpRuleID SG:ICMP rule ID
	SgIcmpRuleID struct {
		IPv uint8
		Sg  string
	}

	// SgSgIcmpRule SG-SG:ICMP default rule
	SgSgIcmpRule struct {
		SgFrom   string
		SgTo     string
		Icmp     ICMP
		Logs     bool
		Trace    bool
		Action   RuleAction
		Priority RulePriority
	}

	// SgSgIcmpRuleID SG-SG:ICMP rule ID
	SgSgIcmpRuleID struct {
		IPv    uint8
		SgFrom string
		SgTo   string
	}

	// IESgSgIcmpRule <IN|E>GRESS:SG-SG:ICMP rule
	IESgSgIcmpRule struct {
		Traffic  Traffic
		SgLocal  string
		Sg       string
		Icmp     ICMP
		Logs     bool
		Trace    bool
		Action   RuleAction
		Priority RulePriority
	}

	// IESgSgIcmpRuleID <IN|E>GRESS:SG-SG:ICMP rule ID
	IESgSgIcmpRuleID struct {
		Traffic Traffic
		IPv     uint8
		SgLocal string
		Sg      string
	}

	// IECidrSgIcmpRule <IN|E>GRESS:CIDR-SG:ICMP rule
	IECidrSgIcmpRule struct {
		Traffic  Traffic
		CIDR     net.IPNet
		SG       string
		Icmp     ICMP
		Logs     bool
		Trace    bool
		Action   RuleAction
		Priority RulePriority
	}

	// IECidrSgIcmpRuleID <IN|E>GRESS:CIDR-SG:ICMP rule ID
	IECidrSgIcmpRuleID struct {
		Traffic Traffic
		IPv     uint8
		SG      string
		CIDR    net.IPNet
	}
)

var (
	_ ruleID[SGRuleIdentity]      = (*SGRuleIdentity)(nil)
	_ ruleID[FQDNRuleIdentity]    = (*FQDNRuleIdentity)(nil)
	_ ruleID[IECidrSgRuleIdenity] = (*IECidrSgRuleIdenity)(nil)
	_ ruleID[IESgSgRuleIdentity]  = (*IESgSgRuleIdentity)(nil)
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

const (
	// RA_UNDEF -
	RA_UNDEF RuleAction = iota

	// RA_DROP setups rule to drop packet
	RA_DROP

	// RA_ACCEPT setups rule to accept packet
	RA_ACCEPT
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

// String impl Stringer
func (a RuleAction) String() string {
	return [...]string{"undef", "drop", "accept"}[a]
}

// FromString init from string
func (a *RuleAction) FromString(s string) error {
	const api = "RuleAction/FromString"
	switch strings.ToLower(s) {
	case "drop":
		*a = RA_DROP
	case "accept":
		*a = RA_ACCEPT
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
	return sg.DefaultAction == other.DefaultAction &&
		sg.Logs == other.Logs &&
		sg.Trace == other.Trace &&
		sg.Name == other.Name &&
		sg.Networks.Eq(&other.Networks)
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
		rule.Trace == other.Trace &&
		rule.Action == other.Action &&
		rule.Priority.IsEq(other.Priority)
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
		o.Action == other.Action &&
		o.Sg == other.Sg &&
		o.Icmp.IsEq(other.Icmp)
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
		o.Action == other.Action &&
		o.Priority.IsEq(other.Priority) &&
		o.SgFrom == other.SgFrom &&
		o.Icmp.IsEq(other.Icmp)
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

// IsEq -
func (o IESgSgIcmpRule) IsEq(other IESgSgIcmpRule) bool {
	return o.Traffic == other.Traffic &&
		o.SgLocal == other.SgLocal &&
		o.Sg == other.Sg &&
		o.Icmp.IsEq(other.Icmp) &&
		o.Logs == other.Logs &&
		o.Trace == other.Trace &&
		o.Action == other.Action &&
		o.Priority.IsEq(other.Priority)
}

// ID -
func (o IESgSgIcmpRule) ID() IESgSgIcmpRuleID {
	return IESgSgIcmpRuleID{
		Traffic: o.Traffic,
		IPv:     o.Icmp.IPv,
		SgLocal: o.SgLocal,
		Sg:      o.Sg,
	}
}

// IdentityHash -
func (o IESgSgIcmpRuleID) IdentityHash() string {
	return o.String()
}

// String -
func (o IESgSgIcmpRuleID) String() string {
	return fmt.Sprintf("icmp%v:sg-local(%s)sg(%s)%s", o.IPv, o.SgLocal, o.Sg, o.Traffic)
}

// IsEq -
func (o IECidrSgIcmpRule) IsEq(other IECidrSgIcmpRule) bool {
	cidrIsEq := o.CIDR.IP.Equal(other.CIDR.IP) &&
		bytes.Equal(o.CIDR.Mask, other.CIDR.Mask)

	return o.Traffic == other.Traffic &&
		o.Icmp.IsEq(other.Icmp) &&
		cidrIsEq &&
		o.SG == other.SG &&
		o.Logs == other.Logs &&
		o.Trace == other.Trace &&
		o.Action == other.Action &&
		o.Priority.IsEq(other.Priority)
}

// ID -
func (o IECidrSgIcmpRule) ID() IECidrSgIcmpRuleID {
	return IECidrSgIcmpRuleID{
		Traffic: o.Traffic,
		IPv:     o.Icmp.IPv,
		CIDR:    o.CIDR,
		SG:      o.SG,
	}
}

// IdentityHash -
func (o IECidrSgIcmpRuleID) IdentityHash() string {
	return o.String()
}

// Cmp -
func (o IECidrSgIcmpRuleID) Cmp(other IECidrSgIcmpRuleID) int {
	if o.Traffic < other.Traffic {
		return -1
	}
	if o.Traffic == other.Traffic {
		if o.IPv < other.IPv {
			return -1
		}
		if o.IPv == other.IPv {
			if o.SG < other.SG {
				return -1
			}
			if o.SG == other.SG {
				var a, b big.Int
				_ = a.SetBytes(o.CIDR.IP)
				_ = b.SetBytes(other.CIDR.IP)
				return a.Cmp(&b)
			}
		}
	}
	return 1
}

// String -
func (o IECidrSgIcmpRuleID) String() string {
	return fmt.Sprintf("icmp%v:cidr(%s)sg(%s)%s", o.IPv, &o.CIDR, o.SG, o.Traffic)
}

// String -
func (o IECidrSgRuleIdenity) String() string {
	return fmt.Sprintf("%s:cidr(%s)sg(%s)%s",
		o.Transport, &o.CIDR, o.SG, o.Traffic)
}

// IdentityHash -
func (o IECidrSgRuleIdenity) IdentityHash() string {
	return o.String()
}

// Cmp -
func (o IECidrSgRuleIdenity) Cmp(other IECidrSgRuleIdenity) int {
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
func (o IECidrSgRuleIdenity) IsEq(other IECidrSgRuleIdenity) bool {
	return o.String() == other.String()
}

// IdentityHash implements ruleID.
func (o IESgSgRuleIdentity) IdentityHash() string {
	return o.String()
}

// IsEq implements ruleID.
func (o IESgSgRuleIdentity) IsEq(other IESgSgRuleIdentity) bool {
	return o.String() == other.String()
}

// String implements ruleID.
func (o IESgSgRuleIdentity) String() string {
	return fmt.Sprintf("%s:sg-local(%s)sg(%s)%s",
		o.Transport, o.SgLocal, o.Sg, o.Traffic)
}

// IsEq -
func (o ICMP) IsEq(other ICMP) bool {
	return o.IPv == other.IPv &&
		o.Types.Eq(&other.Types)
}

// IsEq -
func (o RulePriority) IsEq(other RulePriority) bool {
	return o.ValueOf.IsEq(other.ValueOf, func(a, b int16) bool {
		return a == b
	})
}
