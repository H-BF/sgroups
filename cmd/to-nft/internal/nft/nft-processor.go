package nft

import (
	"context"

	"github.com/H-BF/sgroups/cmd/to-nft/internal/nft/cases"
	pkgErr "github.com/H-BF/sgroups/pkg/errors"

	"github.com/H-BF/corlib/logger"
	sgAPI "github.com/H-BF/protos/pkg/api/sgroups"
	nftLib "github.com/google/nftables"
	"go.uber.org/multierr"
)

// NewNfTablesProcessor creates NfTablesProcessor from SGClient
func NewNfTablesProcessor(client SGClient, opts ...NfTablesProcessorOpt) NfTablesProcessor {
	ret := &nfTablesProcessorImpl{
		sgClient: client,
	}
	for _, o := range opts {
		switch t := o.(type) {
		case WithNetNS:
			ret.netNS = t.NetNS
		}
	}
	return ret
}

type (
	// SGClient is a type alias
	SGClient = sgAPI.SecGroupServiceClient

	nfTablesProcessorImpl struct {
		sgClient SGClient
		netNS    string
	}

	ipVersion = int
)

// ApplyConf impl 'NfTablesProcessor'
func (impl *nfTablesProcessorImpl) ApplyConf(ctx context.Context, conf NetConf) error {
	const api = "ApplyConf"

	var (
		err        error
		localRules cases.LocalRules
		localSGs   cases.LocalSGs
		tx         *nfTablesTx
	)

	localIPsV4, loaclIPsV6 := conf.LocalIPs()
	allLoaclIPs := append(localIPsV4, loaclIPsV6...)
	if err = localSGs.Load(ctx, impl.sgClient, allLoaclIPs); err != nil {
		return multierr.Combine(ErrNfTablesProcessor,
			err, pkgErr.ErrDetails{Api: api, Details: allLoaclIPs})
	}
	if err = localRules.Load(ctx, impl.sgClient, localSGs); err != nil {
		return multierr.Combine(ErrNfTablesProcessor,
			err, pkgErr.ErrDetails{Api: api})
	}

	if tx, err = nfTx(impl.netNS); err != nil { //start nft transaction
		return multierr.Combine(ErrNfTablesProcessor, err,
			pkgErr.ErrDetails{Api: api})
	}
	defer tx.Close()

	tblMain := &nftLib.Table{
		Name:   "main",
		Family: nftLib.TableFamilyINet,
	}

	log := logger.FromContext(ctx)
	log.SugaredLogger = log.Named("nft")
	if len(impl.netNS) > 0 {
		log.SugaredLogger = log.SugaredLogger.With("NetNS", impl.netNS)
	}
	err = (&batch{log: log}).execute(tx, tblMain, localRules)
	if err != nil {
		return multierr.Combine(ErrNfTablesProcessor, err,
			pkgErr.ErrDetails{Api: api})
	}
	return nil
}

// Close impl 'NfTablesProcessor'
func (impl *nfTablesProcessorImpl) Close() error {
	return nil
}
