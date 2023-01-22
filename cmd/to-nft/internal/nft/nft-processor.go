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
		aggRules   cases.AggSgRules
		tx         *nfTablesTx
	)

	effIPv4, effIPv6 := conf.EffectiveIPs()
	allEffectiveIPs := append(effIPv4, effIPv6...)
	if err = aggIPsBySG.Load(ctx, impl.sgClient, allEffectiveIPs); err != nil {
		return multierr.Combine(ErrNfTablesProcessor,
			err, pkgErr.ErrDetails{Api: api, Details: allEffectiveIPs})
	}
	aggIPsBySG.Dedup()

	if sgNames := aggIPsBySG.GetSGNames(); len(sgNames) > 0 {
		sgsVars := []struct {
			from, to []string
		}{{nil, sgNames}, {sgNames, nil}}
		for _, arg := range sgsVars {
			if err = aggRules.Load(ctx, impl.sgClient, arg.from, arg.to); err != nil {
				return multierr.Combine(ErrNfTablesProcessor,
					err, pkgErr.ErrDetails{Api: api})
			}
		}
		aggRules.Dedup()
		effSGs := aggIPsBySG.EffectiveSGs()
		for i := range aggRules {
			r := &aggRules[i]
			if sg, ok := effSGs[r.SgFrom.Name]; ok {
				r.SgFrom = sg
			}
			if sg, ok := effSGs[r.SgTo.Name]; ok {
				r.SgTo = sg
			}
		}
	}

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

	if useIPv4, useIPv6 := len(effIPv4) > 0, len(effIPv6) > 0; useIPv4 || useIPv6 {
		usedSGs := aggRules.UsedSGs()
		for _, sg := range usedSGs {
			if err = tx.applyNetSets(tblMain, sg, useIPv4, useIPv6); err != nil {
				return multierr.Combine(ErrNfTablesProcessor, err,
					pkgErr.ErrDetails{Api: api, Details: sg})
			}
		}
	}

	//add set(s) with <TCP|UDP> <S|D> port range(s)
	for _, rule := range aggRules {
		if err = tx.applyPortSets(tblMain, rule); err != nil {
			return multierr.Combine(ErrNfTablesProcessor, err,
				pkgErr.ErrDetails{Api: api, Details: aggRules})
		}
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
