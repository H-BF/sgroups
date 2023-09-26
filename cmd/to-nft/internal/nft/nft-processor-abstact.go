package nft

import (
	"context"
	"net"

	"github.com/H-BF/sgroups/cmd/to-nft/internal"
	"github.com/H-BF/sgroups/cmd/to-nft/internal/nft/cases"
	"github.com/H-BF/sgroups/internal/config"
	model "github.com/H-BF/sgroups/internal/models/sgroups"

	"github.com/c-robinson/iplib"
)

type (
	// AppliedRules -
	AppliedRules struct {
		TargetTable  string
		BaseRules    BaseRules
		SG2SGRules   cases.SG2SGRules
		SG2FQDNRules cases.SG2FQDNRules
	}

	// Patch -
	Patch interface {
		isAppliedRulesPatch()
	}

	// UpdateFqdnNetsets
	UpdateFqdnNetsets struct {
		IPVersion int
		FQDN      model.FQDN
		Addresses []net.IP
	}

	// NfTablesProcessorOpt constructor option(s)
	NfTablesProcessorOpt interface {
		isNfTablesProcessorOpt()
	}

	// NfTablesProcessor abstract interface
	NfTablesProcessor interface {
		ApplyConf(ctx context.Context, conf NetConf) (AppliedRules, error)
		Patch(ctx context.Context, rules AppliedRules, p Patch) error
		Close() error
	}

	// WithNetNS use network namespace
	WithNetNS struct {
		NetNS string
	}

	// BaseRules -
	BaseRules struct {
		Nets []config.NetCIDR
	}

	// DnsResolver -
	DnsResolver struct {
		internal.DomainAddressQuerier
	}
)

var (
	_ Patch = (*UpdateFqdnNetsets)(nil)
)

func (UpdateFqdnNetsets) isAppliedRulesPatch() {}

// NetSet -
func (ns UpdateFqdnNetsets) NetSet() []net.IPNet {
	isV6 := ns.IPVersion == iplib.IP6Version
	bits := tern(isV6, net.IPv6len, net.IPv4len) * 8
	mask := net.CIDRMask(bits, bits)
	ret := make([]net.IPNet, len(ns.Addresses))
	for i, ip := range ns.Addresses {
		ret[i] = net.IPNet{IP: ip, Mask: mask}
	}
	return ret
}

//DNS resolver

func (WithNetNS) isNfTablesProcessorOpt()   {}
func (BaseRules) isNfTablesProcessorOpt()   {}
func (DnsResolver) isNfTablesProcessorOpt() {}
