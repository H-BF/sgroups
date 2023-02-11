package nft

import (
	"net"
	"sync"

	"github.com/c-robinson/iplib"
	nftLib "github.com/google/nftables"
	"github.com/pkg/errors"
	"github.com/vishvananda/netns"
)

type nfTablesTx struct {
	*nftLib.Conn
	commitOnce sync.Once
}

func nfTx(netNS string) (*nfTablesTx, error) {
	const api = "connect to nft"

	opts := []nftLib.ConnOption{nftLib.AsLasting()}
	if len(netNS) > 0 {
		n, e := netns.GetFromName(netNS)
		if e != nil {
			return nil, errors.WithMessagef(e,
				"%s: accessing netns '%s'", api, netNS)
		}
		opts = append(opts, nftLib.WithNetNSFd(int(n)))
		defer n.Close()
	}
	c, e := nftLib.New(opts...)
	if e != nil {
		return nil, errors.WithMessage(e, api)
	}
	return &nfTablesTx{Conn: c}, nil
}

// Close impl 'Closer'
func (tx *nfTablesTx) Close() error {
	c := tx.Conn
	tx.commitOnce.Do(func() {
		_ = c.CloseLasting()
	})
	return nil
}

// loadConfig it loads current config (experimental)
func (tx *nfTablesTx) loadConfig() {
	type (
		tn = string
		tk = struct {
			nftLib.TableFamily
			tn
		}
		chain = struct {
			*nftLib.Chain
			rules []*nftLib.Rule
		}
		sets   = dict[string, *nftLib.Set]
		chains = dict[string, *chain]
		table  = struct {
			tbl *nftLib.Table
			sets
			chains
		}
		tables = dict[tk, *table]
	)
	var (
		savedTables tables
		chainList   []*nftLib.Chain
		tableList   []*nftLib.Table
		err         error
	)
	if chainList, err = tx.ListChains(); err == nil {
		for _, chn := range chainList {
			k := tk{chn.Table.Family, chn.Table.Name}
			tb := savedTables.at(k)
			if tb == nil {
				tb = &table{
					tbl: chn.Table,
				}
				savedTables.put(k, tb)
			}
			if cx := tb.chains.at(chn.Name); cx == nil {
				cx := &chain{Chain: chn}
				tb.chains.put(chn.Name, cx)
			}
		}
	}
	if tableList, err = tx.ListTables(); err == nil {
		for _, tb := range tableList {
			k := tk{tb.Family, tb.Name}
			if _, ok := savedTables.get(k); !ok {
				savedTables.put(k, &table{
					tbl: tb,
				})
			}
		}
	}
	savedTables.iterate(func(k tk, t *table) bool {
		sts, e := tx.GetSets(t.tbl)
		if e != nil {
			return false
		}
		for _, st := range sts {
			t.sets.put(st.Name, st)
		}
		t.chains.iterate(func(_ string, chn *chain) bool {
			rls, e1 := tx.GetRules(chn.Table, chn.Chain)
			if e1 != nil {
				return false
			}
			chn.rules = rls
			return true
		})
		return true
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
