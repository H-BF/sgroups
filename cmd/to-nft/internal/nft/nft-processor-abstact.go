package nft

import (
	"context"
)

type NfTablesProcessor interface {
	ApplyConf(ctx context.Context, conf NetConf) error
}
