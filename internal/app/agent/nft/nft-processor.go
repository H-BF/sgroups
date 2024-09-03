package nft

import (
	"context"

	"github.com/H-BF/sgroups/v2/internal/app/agent/nft/resources"

	"github.com/H-BF/corlib/logger"
	sgAPI "github.com/H-BF/protos/pkg/api/sgroups"
	"github.com/pkg/errors"
	uuid "github.com/satori/go.uuid"
	"go.uber.org/multierr"
)

// NewNfTablesProcessor creates NfTablesProcessor from SGClient
func NewNfTablesProcessor(client SGClient, opts ...NfTablesProcessorOpt) NfTablesProcessor {
	ret := new(nfTablesProcessorImpl)
	for _, o := range opts {
		switch t := o.(type) {
		case WithNetNS:
			ret.netNS = t.NetNS
		case BaseRules:
			ret.baseRules = t
		}
	}
	return ret
}

type (
	// SGClient is a type alias
	SGClient = sgAPI.SecGroupServiceClient

	nfTablesProcessorImpl struct {
		netNS     string
		baseRules BaseRules
	}

	ipVersion = int
)

// ApplyConf impl 'NfTablesProcessor'
func (impl *nfTablesProcessorImpl) ApplyConf(ctx context.Context, data resources.LocalData) (applied AppliedRules, err error) {
	const api = "nft/ApplyConf"

	log := logger.FromContext(ctx).Named("nft").Named("ApplyConf")
	if len(impl.netNS) > 0 {
		log = log.WithField("net-ns", impl.netNS)
	}
	log.Info("begin")
	defer func() {
		if err == nil {
			log.Info("succeeded")
		} else {
			log.Error(err)
			err = errors.WithMessage(multierr.Combine(
				ErrNfTablesProcessor, err,
			), api)
		}
	}()

	pfm := BatchPerformer{
		TableName: "main",
		Tx: func() (*Tx, error) {
			return NewTx(impl.netNS)
		},
	}
	err = pfm.Exec(ctx,
		data,
		WithLogger(log),
		WithBaseRules(impl.baseRules),
	)
	if err == nil {
		applied.LocalData = data
		applied.BaseRules = impl.baseRules
		applied.TargetTable = pfm.TableName
		applied.NetNS = impl.netNS
		applied.ID = uuid.NewV4()
	}
	return applied, err
}

// Close impl 'NfTablesProcessor'
func (impl *nfTablesProcessorImpl) Close() error {
	return nil
}
