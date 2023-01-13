package nft

import (
	"context"
)

// NfTablesProcessor abstract interface
type NfTablesProcessor interface {
	ApplyConf(ctx context.Context, conf NetConf) error
	Close() error
}
