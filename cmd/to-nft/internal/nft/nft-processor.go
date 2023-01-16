package nft

import (
	"context"

	sgAPI "github.com/H-BF/protos/pkg/api/sgroups"
	"github.com/H-BF/sgroups/cmd/to-nft/internal/nft/cases"
	pkgErr "github.com/H-BF/sgroups/pkg/errors"
	"github.com/c-robinson/iplib"
	nftLib "github.com/google/nftables"
	"go.uber.org/multierr"
)

// NewNfTablesProcessor creates NfTablesProcessor from SGClient
func NewNfTablesProcessor(_ context.Context, client SGClient) NfTablesProcessor {
	return &nfTablesProcessorImpl{
		sgClient: client,
	}
}

type (
	// SGClient is a type alias
	SGClient = sgAPI.SecGroupServiceClient

	nfTablesProcessorImpl struct {
		sgClient SGClient
	}

	ipVersion = int
)

const (
	ipV4 ipVersion = iplib.IP4Version
	ipV6 ipVersion = iplib.IP6Version
)

// ApplyConf impl 'NfTablesProcessor'
func (impl *nfTablesProcessorImpl) ApplyConf(ctx context.Context, conf NetConf) error {
	const api = "ApplyConf"

	var (
		err        error
		aggIPsBySG cases.IPsBySG
		aggSgToSgs cases.SgToSgs
		tx         *nfTablesTx
	)

	actualIPs := conf.ActualIPs()
	if err = aggIPsBySG.Load(ctx, impl.sgClient, actualIPs); err != nil {
		return multierr.Combine(ErrNfTablesProcessor,
			err, pkgErr.ErrDetails{Api: api})
	}
	aggIPsBySG.Dedup()

	sgNames := aggIPsBySG.GetSGNames()
	if err = aggSgToSgs.Load(ctx, impl.sgClient, sgNames, sgNames); err != nil {
		return multierr.Combine(ErrNfTablesProcessor,
			err, pkgErr.ErrDetails{Api: api})
	}
	aggSgToSgs.Dedup()

	if tx, err = nfTx(); err != nil { //start nft transaction
		return multierr.Combine(ErrNfTablesProcessor, err,
			pkgErr.ErrDetails{Api: api})
	}
	defer tx.abort()

	tx.FlushRuleset() //delete all defs

	tblMain := &nftLib.Table{
		Name:   "main",
		Family: nftLib.TableFamilyINet,
	}
	_ = tx.AddTable(tblMain) //add table 'main'

	sgAgg4, sgAgg6 := aggIPsBySG.SeparateV4andV6()
	//add set(s) with IP4 address(es)
	if err = tx.applyIPSets(tblMain, sgAgg4, ipV4); err != nil {
		return multierr.Combine(ErrNfTablesProcessor, err,
			pkgErr.ErrDetails{Api: api, Details: sgAgg4})
	}

	//add set(s) with IP6 address(es)
	if err = tx.applyIPSets(tblMain, sgAgg6, ipV6); err != nil {
		return multierr.Combine(ErrNfTablesProcessor, err,
			pkgErr.ErrDetails{Api: api, Details: sgAgg6})
	}

	//add set(s) with <TCP|UDP> <S|D> port range(s)
	if err = tx.applyPortSets(tblMain, aggSgToSgs); err != nil {
		return multierr.Combine(ErrNfTablesProcessor, err,
			pkgErr.ErrDetails{Api: api, Details: aggSgToSgs})
	}

	//nft commit
	if err = tx.commit(); err != nil {
		return multierr.Combine(ErrNfTablesProcessor, err,
			pkgErr.ErrDetails{Api: api})
	}

	return nil
}

// Close impl 'NfTablesProcessor'
func (impl *nfTablesProcessorImpl) Close() error {
	return nil
}
