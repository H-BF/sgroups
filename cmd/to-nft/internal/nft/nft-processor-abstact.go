package nft

import (
	"context"
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
	NfTablesProcessorOpt
	NetNS string
}
