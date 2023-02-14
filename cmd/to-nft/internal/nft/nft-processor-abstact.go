package nft

import (
	"context"

	"github.com/H-BF/corlib/logger"
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

// WithLoger adds logger
type WithLoger struct {
	NfTablesProcessorOpt
	Logger logger.TypeOfLogger
}

// WithNetNS use network namespace
type WithNetNS struct {
	NfTablesProcessorOpt
	NetNS string
}
