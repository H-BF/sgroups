package nft

import (
	"math"
	"net"
	"sync"

	model "github.com/H-BF/sgroups/internal/models/sgroups"
	"github.com/c-robinson/iplib"
	nftLib "github.com/google/nftables"
	nftLibUtil "github.com/google/nftables/binaryutil"
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

func (tx *nfTablesTx) applyNetSets(tbl *nftLib.Table, sg model.SecurityGroup, useIPv4, useIPv6 bool) error {
	const (
		api  = "ntf/apply-net-sets"
		b32  = 32
		b128 = 128
	)

	var elementsV4 []nftLib.SetElement
	var elementsV6 []nftLib.SetElement
	items := []struct {
		ty  nftLib.SetDatatype
		els *[]nftLib.SetElement
		ipV ipVersion
	}{
		{nftLib.TypeIPAddr, &elementsV4, ipV4},
		{nftLib.TypeIP6Addr, &elementsV6, ipV6},
	}

	for _, nw := range sg.Networks {
		ones, _ := nw.Net.Mask.Size()
		netIf := iplib.NewNet(nw.Net.IP, ones)
		ipLast := iplib.NextIP(netIf.LastAddress())
		switch netIf.Version() {
		case ipV4:
			if useIPv4 {
				if ones < b32 {
					ipLast = iplib.NextIP(ipLast)
				}
				elementsV4 = append(elementsV4, nftLib.SetElement{
					Key:    nw.Net.IP,
					KeyEnd: ipLast,
				})
			}
		case ipV6:
			if useIPv6 {
				if ones < b128 {
					ipLast = iplib.NextIP(ipLast)
				}
				elementsV6 = append(elementsV6, nftLib.SetElement{
					Key:    nw.Net.IP,
					KeyEnd: ipLast,
				})
			}
		}
	}

	for _, it := range items {
		if els := *it.els; len(els) > 0 {
			netSet := &nftLib.Set{
				Table:    tbl,
				KeyType:  it.ty,
				Interval: true,
				Name:     nameUtils{}.nameOfNetSet(it.ipV, sg.Name),
			}
			if err := tx.AddSet(netSet, els); err != nil {
				return errors.WithMessagef(err, "%s: add set", api)
			}
		}
	}
	return nil
}

func (tx *nfTablesTx) applyPortSets(tbl *nftLib.Table, rule model.SGRule) error {
	const api = "ntf/apply-port-sets"

	var (
		names nameUtils
		err   error
		be    = nftLibUtil.BigEndian
	)

	pranges := []model.PortRanges{rule.PortsFrom, rule.PortsTo}
	for i := range pranges {
		var elemnts []nftLib.SetElement
		pranges[i].Iterate(func(r model.PortRange) bool {
			a, b := r.Bounds()
			b = b.AsExcluded()
			aVal, _ := a.GetValue()
			bVal, _ := b.GetValue()
			if aVal > math.MaxUint16 || bVal > math.MaxUint16 {
				err = ErrPortRange
				return false //error
			}
			elemnts = append(elemnts,
				nftLib.SetElement{
					Key:    be.PutUint16(uint16(aVal)),
					KeyEnd: be.PutUint16(uint16(bVal)),
				},
			)
			return true
		})
		if err != nil {
			return errors.WithMessage(err, api)
		}
		if len(elemnts) > 0 {
			portSet := &nftLib.Set{
				Table: tbl,
				Name: names.nameOfPortSet(
					rule.Transport, rule.SgFrom.Name,
					rule.SgTo.Name, i > 0),
				KeyType:  nftLib.TypeInetService,
				Interval: true,
			}
			if err = tx.AddSet(portSet, elemnts); err != nil {
				return errors.WithMessagef(err, "%s: add set", api)
			}
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
	return errors.Errorf("%s: commit on closed", api)
}

func (tx *nfTablesTx) abort() {
	c := tx.Conn
	tx.commitOnce.Do(func() {
		_ = c.CloseLasting()
	})
}

var (
	_ = ipToReverseBytes
)

func reverseBytes(p []byte) {
	for i, j := 0, len(p)-1; i < j && j >= 0; i, j = i+1, j-1 {
		p[i], p[j] = p[j], p[i]
	}
}

func ipToReverseBytes(ip net.IP) []byte {
	ipAsInt := iplib.IPToBigint(ip)
	b := ipAsInt.Bytes()
	reverseBytes(b)
	return b
}
