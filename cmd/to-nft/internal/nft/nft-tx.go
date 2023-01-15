package nft

import (
	"sync"

	"github.com/H-BF/sgroups/cmd/to-nft/internal/nft/cases"
	model "github.com/H-BF/sgroups/internal/models/sgroups"
	nftLib "github.com/google/nftables"
	"github.com/pkg/errors"
)

type nfTablesTx struct {
	*nftLib.Conn
	commitOnce sync.Once
}

func nfTx() (*nfTablesTx, error) {
	c, e := nftLib.New(nftLib.AsLasting())
	if e != nil {
		return nil, errors.WithMessage(e, "open nft tx")
	}
	return &nfTablesTx{Conn: c}, nil
}

func (tx *nfTablesTx) applyIPSets(tbl *nftLib.Table, agg cases.IPsBySG, ipV ipVersion) error {
	const api = "ntf/apply-IP-sets"

	for _, x := range agg {
		if x.IPs.Len() == 0 {
			continue
		}
		ipSet := &nftLib.Set{
			Table: tbl,
			Name:  nameUtils{}.nameOfAddrSet(ipV, x.SG.Name),
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

func (tx *nfTablesTx) applyPortSets(tbl *nftLib.Table, agg cases.SgToSgs) error {
	const api = "ntf/apply-port-sets"
	_ = api

	for k, items := range agg {
		_ = k
		for _, item := range *items {
			item.PortsFrom.Iterate(func(r model.PortRange) bool {
				_, _ = r.Bounds()
				return true
			})
			item.PortsTo.Iterate(func(r model.PortRange) bool {
				return true
			})
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
