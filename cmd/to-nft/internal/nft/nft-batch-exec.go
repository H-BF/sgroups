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
		TableName string
		Tx        TxProvider
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

// WithNetworks -
func WithNetworks(nws cases.SGsNetworks) funcBatchOpt {
	return func(b *batch) {
		b.networks = nws
	}
}

// WithBaseRules -
func WithBaseRules(baseRules BaseRules) funcBatchOpt {
	return func(b *batch) {
		b.baseRules = baseRules
	}
}

// WithSg2SgRules -
func WithSg2SgRules(r cases.SG2SGRules) funcBatchOpt {
	return func(b *batch) {
		b.localRules = r
	}
}

// WithSg2FqdnRules -
func WithSg2FqdnRules(r cases.SG2FQDNRules) funcBatchOpt {
	return func(b *batch) {
		b.sg2fqdnRules = r
	}
}

// WithSgSgIcmpRules -
func WithSgSgIcmpRules(r cases.SgSgIcmpRules) funcBatchOpt {
	return func(b *batch) {
		b.sg2sgIcmpRules = r
	}
}

// WithSgSgIcmpRules -
func WithSgIcmpRules(r cases.SgIcmpRules) funcBatchOpt {
	return func(b *batch) {
		b.sgIcmpRules = r
	}
}
