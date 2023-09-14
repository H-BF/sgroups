package nft

import (
	"context"

	"github.com/H-BF/sgroups/cmd/to-nft/internal/dns"
	"github.com/H-BF/sgroups/cmd/to-nft/internal/nft/cases"
	"github.com/H-BF/sgroups/internal/config"
)

type (
	// AppliedRules -
	AppliedRules struct {
		TargetTable  string
		SavedNftConf NFTablesConf
		BaseRules    BaseRules
		SG2SGRules   cases.SG2SGRules
		SG2FQDNRules cases.SG2FQDNRules
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
		dns.Resolver
	}
)

//DNS resolver

func (WithNetNS) isNfTablesProcessorOpt()   {}
func (BaseRules) isNfTablesProcessorOpt()   {}
func (DnsResolver) isNfTablesProcessorOpt() {}
