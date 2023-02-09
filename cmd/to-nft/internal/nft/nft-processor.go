package nft

import (
	"context"

	"github.com/H-BF/sgroups/cmd/to-nft/internal/nft/cases"
	pkgErr "github.com/H-BF/sgroups/pkg/errors"
	"golang.org/x/sys/unix"

	sgAPI "github.com/H-BF/protos/pkg/api/sgroups"
	nftLib "github.com/google/nftables"
	"go.uber.org/multierr"
)

// NewNfTablesProcessor creates NfTablesProcessor from SGClient
func NewNfTablesProcessor(_ context.Context, client SGClient, netNS string) NfTablesProcessor {
	return &nfTablesProcessorImpl{
		sgClient: client,
		netNS:    netNS,
	}
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
	defer tx.abort()

	tblMain := &nftLib.Table{
		Name:   "main",
		Family: nftLib.TableFamilyINet,
	}
	//delete table 'main'
	if err = tx.deleteTables(tblMain); err != nil {
		return err
	}
	_ = tx.AddTable(tblMain) //add table 'main'

	var namesOfNetSets generatedSets
	var namesOfPortSets generatedSets

	namesOfNetSets, err = tx.applyNetSets(tblMain, localRules)
	if err != nil {
		return multierr.Combine(ErrNfTablesProcessor, err,
			pkgErr.ErrDetails{Api: api})
	}
	namesOfPortSets, err = tx.applyPortSets(tblMain, localRules)
	if err != nil {
		return multierr.Combine(ErrNfTablesProcessor, err,
			pkgErr.ErrDetails{Api: api})
	}

	setTcpUdpProtos := &nftLib.Set{
		Table:     tblMain,
		Anonymous: true,
		Constant:  true,
		KeyType:   nftLib.TypeInetProto,
	}
	err = tx.AddSet(setTcpUdpProtos, []nftLib.SetElement{
		{Key: []byte{unix.IPPROTO_TCP}},
		{Key: []byte{unix.IPPROTO_UDP}},
	})
	if err != nil {
		return multierr.Combine(ErrNfTablesProcessor, err,
			pkgErr.ErrDetails{Api: api, Msg: "add 'tcp|upd' proto set"})
	}

	fwOutChain := tx.AddChain(&nftLib.Chain{
		Name:  "FW-OUT",
		Table: tblMain,
	})
	err = tx.fillWithOutRules(fwOutChain, localRules, setTcpUdpProtos,
		namesOfNetSets, namesOfPortSets)
	if err != nil {
		return multierr.Combine(ErrNfTablesProcessor, err,
			pkgErr.ErrDetails{Api: api})
	}
	beginRule().
		drop().
		applyRule(fwOutChain, tx.Conn)

	fwInChain := tx.AddChain(&nftLib.Chain{
		Name:  "FW-IN",
		Table: tblMain,
	})
	/*//
	err = tx.fillWithInRules(fwInChain, localRules, setTcpUdpProtos,
		namesOfNetSets, namesOfPortSets)
	if err != nil {
		return multierr.Combine(ErrNfTablesProcessor, err,
			pkgErr.ErrDetails{Api: api})
	}
	*/
	beginRule().
		drop().
		applyRule(fwInChain, tx.Conn)

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
