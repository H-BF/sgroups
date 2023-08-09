package nft

import (
	"context"

	"github.com/H-BF/sgroups/internal/config"
)

// NfTablesProcessorOpt constructor option(s)
type NfTablesProcessorOpt interface {
	isNfTablesProcessorOpt()
}

// NfTablesProcessor abstract interface
type NfTablesProcessor interface {
	ApplyConf(ctx context.Context, conf NetConf) error
	Close() error
}

// WithNetNS use network namespace
type WithNetNS struct {
	NetNS string
}

// BaseRules -
type BaseRules struct {
	Nets []config.NetCIDR
}

func (WithNetNS) isNfTablesProcessorOpt() {}
func (BaseRules) isNfTablesProcessorOpt() {}
