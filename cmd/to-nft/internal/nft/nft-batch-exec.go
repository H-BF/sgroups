//go:build linux
// +build linux

package nft

import (
	"context"

	"github.com/H-BF/sgroups/cmd/to-nft/internal/nft/cases"

	"github.com/H-BF/corlib/logger"
)

type (
	// TxProvider -
	TxProvider func() (*Tx, error)

	// BatchOpt -
	BatchOpt interface {
		apply(*batch)
	}

	// BatchPerformer -
	BatchPerformer struct {
		TableName  string
		Tx         TxProvider
		LocalRules cases.SG2SGRules
	}

	funcBatchOpt func(*batch)
)

// Exec -
func (exc BatchPerformer) Exec(ctx context.Context, opts ...BatchOpt) error {
	b := batch{
		log:        logger.FromContext(ctx),
		tableName:  exc.TableName,
		txProvider: exc.Tx,
	}
	for _, o := range opts {
		o.apply(&b)
	}
	return b.execute(ctx)
}

func (f funcBatchOpt) apply(b *batch) {
	f(b)
}

// WithLogger -
func WithLogger(l logger.TypeOfLogger) funcBatchOpt {
	return func(b *batch) {
		b.log = l
	}
}

// WithBaseRules -
func WithBaseRules(baseRules BaseRules) funcBatchOpt {
	return func(b *batch) {
		b.baseRules = baseRules
	}
}

// WithSg2FqdnRules -
func WithSg2FqdnRules(r cases.SG2FQDNRules) funcBatchOpt {
	return func(b *batch) {
		b.sg2fqdnRules = r
	}
}
