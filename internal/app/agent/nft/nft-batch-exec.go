//go:build linux
// +build linux

package nft

import (
	"context"

	"github.com/H-BF/sgroups/internal/app/agent"
	"github.com/H-BF/sgroups/internal/app/agent/nft/resources"

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
func (exc *BatchPerformer) Exec(ctx context.Context, data resources.LocalData, opts ...BatchOpt) error {
	b := &batch{
		log:          logger.FromContext(ctx),
		txProvider:   exc.Tx,
		data:         data,
		dnsResolver:  agent.GetDnsResolver(),
		fqdnStrategy: agent.FqdnStrategy.MustValue(ctx),
	}
	for _, o := range opts {
		o.apply(b)
	}
	e := b.execute(ctx)
	if e == nil {
		exc.TableName = b.table.Name
	} else {
		_ = b.cleanOnFail(ctx)
	}
	return e
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
