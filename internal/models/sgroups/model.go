package sgroups

import (
	"crypto/md5" //nolint:gosec
	"encoding/hex"
	"fmt"
	"net"
	"strings"

	"github.com/H-BF/corlib/pkg/ranges"
)

type (
	//PortNumber net port num
	PortNumber = uint32

	//PortRanges net port ranges
	PortRanges = ranges.MultiRange[PortNumber]

	//PortRange net port range
	PortRange = ranges.Range[PortNumber]

	//NetworkTransport net transport
	NetworkTransport uint8

	//NetworkName net nam
	NetworkName = string

	//Network is IP network
	Network struct {
		Net  net.IPNet
		Name NetworkName
	}

	//SecurityGroup security group for networks(s)
	SecurityGroup struct {
		Name     string
		Networks []Network
	}

	//SGRuleIdentity security rule ID as key
	SGRuleIdentity struct {
		SgFrom, SgTo SecurityGroup
		Transport    NetworkTransport
	}

	//SGRule security rule for From-To security groups
	SGRule struct {
		SGRuleIdentity
		PortsFrom, PortsTo PortRanges
	}
)

const (
	//TCP ...
	TCP NetworkTransport = iota

	//UDP ...
	UDP
)

//String impl Stringer
func (nt NetworkTransport) String() string {
	return [...]string{"tcp", "udp"}[nt]
}

//IdentityHash makes ID as hash for SGRule
func (sgRuleKey SGRuleIdentity) IdentityHash() string {
	hasher := md5.New() //nolint:gosec
	hasher.Write([]byte(sgRuleKey.SgFrom.Name))
	hasher.Write([]byte(sgRuleKey.SgTo.Name))
	hasher.Write([]byte(sgRuleKey.Transport.String()))
	return strings.ToLower(hex.EncodeToString(hasher.Sum(nil)))
}

//String impl Stringer
func (sgRuleKey SGRuleIdentity) String() string {
	return fmt.Sprintf("'%s'('%s' - '%s')",
		sgRuleKey.Transport, sgRuleKey.SgFrom.Name, sgRuleKey.SgTo.Name)
}
