package nft

import (
	"context"
	"fmt"
	"strings"
	"sync"

	sgAPI "github.com/H-BF/protos/pkg/api/sgroups"
	"github.com/H-BF/sgroups/cmd/to-nft/internal/nft/cases"
	pkgErr "github.com/H-BF/sgroups/pkg/errors"
	"github.com/c-robinson/iplib"
	nftLib "github.com/google/nftables"
	"github.com/pkg/errors"
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

	nfTablesTx struct {
		*nftLib.Conn
		commitOnce sync.Once
	}
)

const (
	ipV4 ipVersion = iplib.IP4Version
	ipV6 ipVersion = iplib.IP6Version
)

// ApplyConf impl 'NfTablesProcessor'
func (impl *nfTablesProcessorImpl) ApplyConf(ctx context.Context, conf NetConf) error {
	const api = "ApplyConf"

	actualIPs := conf.ActualIPs()
	var sgAgg cases.IPsBySG
	err := sgAgg.Load(ctx, impl.sgClient, actualIPs)
	if err != nil {
		return multierr.Combine(ErrNfTablesProcessor, err, pkgErr.ErrDetails{Api: api})
	}
	sgAgg.Dedup()
	sgAgg4, sgAgg6 := sgAgg.V4andV6()

	var tx *nfTablesTx
	tx, err = nfTx() //start nft transaction
	if err != nil {
		return multierr.Combine(ErrNfTablesProcessor, err, pkgErr.ErrDetails{Api: api})
	}
	defer tx.abort()

	tx.FlushRuleset() //delete all defs

	tblMain := &nftLib.Table{
		Name:   "main",
		Family: nftLib.TableFamilyINet,
	}
	_ = tx.AddTable(tblMain) //create table 'main'

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

func nfTx() (*nfTablesTx, error) {
	c, e := nftLib.New(nftLib.AsLasting())
	if e != nil {
		return nil, errors.WithMessage(e, "open nft tx")
	}
	return &nfTablesTx{Conn: c}, nil
}

func (tx *nfTablesTx) nameOfAddrSet(ipV ipVersion, sgName string) string {
	const prefix = "IPs"

	if sgName = strings.TrimSpace(sgName); len(sgName) == 0 {
		panic("no SG nake is provided")
	}
	switch ipV {
	case ipV4:
		return fmt.Sprintf("V4:%s_%s", prefix, sgName)
	case ipV6:
		return fmt.Sprintf("V6:%s_%s", prefix, sgName)
	}
	panic("wrong IP version is privided")
}

func (tx *nfTablesTx) applyIPSets(tbl *nftLib.Table, agg cases.IPsBySG, ipV ipVersion) error {
	const api = "ntf/apply-IP-sets"

	for _, x := range agg {
		if x.IPs.Len() == 0 {
			continue
		}
		ipSet := &nftLib.Set{
			Table: tbl,
			Name:  tx.nameOfAddrSet(ipV, x.SG.Name),
		}
		switch ipV {
		case ipV4:
			ipSet.KeyType = nftLib.TypeIPAddr
		case ipV6:
			ipSet.KeyType = nftLib.TypeIP6Addr
		default:
			panic("wrong ipV is passed")
		}
		var elements []nftLib.SetElement
		for _, ip := range x.IPs {
			elements = append(elements,
				nftLib.SetElement{
					Key: ip,
				})
		}
		if err := tx.SetAddElements(ipSet, elements); err != nil {
			return errors.WithMessage(err, api)
		}
	}
	return nil
}

func (tx *nfTablesTx) commit() error {
	const api = "ntf/flush"

	c := tx.Conn
	var err error
	var passed bool
	tx.commitOnce.Do(func() {
		err = c.Flush()
		_ = c.CloseLasting()
		passed = true
	})
	if passed {
		return errors.WithMessage(err, api)
	}
	return errors.Errorf("%s: closed", api)
}

func (tx *nfTablesTx) abort() {
	c := tx.Conn
	tx.commitOnce.Do(func() {
		_ = c.CloseLasting()
	})
}
