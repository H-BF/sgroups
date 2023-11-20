package nft

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/H-BF/sgroups/cmd/to-nft/internal"
	"github.com/H-BF/sgroups/cmd/to-nft/internal/nft/cases"
	"github.com/H-BF/sgroups/internal/config"
	model "github.com/H-BF/sgroups/internal/models/sgroups"

	"github.com/c-robinson/iplib"
)

type (
	// AppliedRules -
	AppliedRules struct {
		NetNS         string
		TargetTable   string
		BaseRules     BaseRules
		LocalSGs      cases.SGs
		SG2SGRules    cases.SG2SGRules
		SG2FQDNRules  cases.SG2FQDNRules
		SgIcmpRules   cases.SgIcmpRules
		SgSgIcmpRules cases.SgSgIcmpRules
	}

	// Patch -
	Patch interface {
		String() string
		isAppliedRulesPatch()
	}

	// UpdateFqdnNetsets - is kind of Patch
	UpdateFqdnNetsets struct {
		IPVersion int
		TTL       time.Duration
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

// String impl Stringer interface
func (p UpdateFqdnNetsets) String() string {
	return fmt.Sprintf("fqdn-netset(ip-v: %v; domain: '%s'; addrs: %s)",
		p.IPVersion, p.FQDN, slice2stringer(p.Addresses...))
}

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

// Patch -
func (rules *AppliedRules) Patch(p Patch, apply func() error) error {
	switch v := p.(type) {
	case UpdateFqdnNetsets:
		if !isIn(v.IPVersion, sli(iplib.IP4Version, iplib.IP6Version)) {
			return ErrPatchNotApplicable
		}
		src := tern(v.IPVersion == iplib.IP4Version,
			&rules.SG2FQDNRules.A, &rules.SG2FQDNRules.AAAA)
		if _, ok := src.Get(v.FQDN); !ok {
			break
		}
		if err := apply(); err != nil {
			return err
		}
		src.Put(v.FQDN, internal.DomainAddresses{
			TTL: v.TTL,
			IPs: v.Addresses,
		})
		return nil
	}
	return ErrPatchNotApplicable
}
