//go:build linux
// +build linux

package nft

import (
	"fmt"

	dkt "github.com/H-BF/corlib/pkg/dict"
	"github.com/ahmetb/go-linq/v3"
	nftlib "github.com/google/nftables"
	"github.com/pkg/errors"
)

// NfTableKey -
type NfTableKey struct {
	nftlib.TableFamily
	Name string
}

// NfChainKey -
type NfChainKey struct {
	ChainType nftlib.ChainType
	Name      string
}

// NfSet -
type NfSet struct {
	*nftlib.Set
	Elements []nftlib.SetElement
}

// NfChain -
type NfChain struct {
	*nftlib.Chain
	Rules []*nftlib.Rule
}

// NFTablesConf -
type NFTablesConf struct {
	Tables dkt.HDict[NfTableKey, *nftlib.Table]
	Sets   dkt.HDict[NfTableKey, dkt.HDict[string, NfSet]]
	Chains dkt.HDict[NfTableKey, dkt.HDict[NfChainKey, NfChain]]
}

// String -
func (k NfTableKey) String() string {
	return fmt.Sprintf("key(name: '%s', family: %v)", k.Name, k.TableFamily)
}

// String -
func (k NfChainKey) String() string {
	return fmt.Sprintf("key(name: '%s', type: '%s')", k.Name, k.ChainType)
}

func (cnf *NFTablesConf) Load(conn *nftlib.Conn) error {
	for _, c := range sli(cnf.Tables.Clear, cnf.Chains.Clear, cnf.Sets.Clear) {
		c()
	}
	var err error
	for _, ld := range sli(cnf.loadTables, cnf.loadSets, cnf.loadChains) {
		if err = ld(conn); err != nil {
			break
		}
	}
	return err
}

func (cnf *NFTablesConf) loadTables(conn *nftlib.Conn) (err error) {
	const api = "nft/load-tables"
	defer func() {
		err = errors.WithMessage(err, api)
	}()
	var tbs []*nftlib.Table
	tbs, err = conn.ListTables()
	linq.From(tbs).
		SkipWhile(func(_ any) bool {
			return err != nil
		}).
		ForEach(func(i any) {
			t := i.(*nftlib.Table)
			k := NfTableKey{t.Family, t.Name}
			if !cnf.Tables.Insert(k, t) {
				err = fmt.Errorf("table {%s} is not unique", k)
				return
			}
		})
	return err
}

func (cnf *NFTablesConf) loadSets(conn *nftlib.Conn) (err error) {
	const api = "nft/load-sets"
	defer func() {
		err = errors.WithMessage(err, api)
	}()
	cnf.Tables.Iterate(func(k NfTableKey, v *nftlib.Table) bool {
		defer func() {
			err = errors.WithMessagef(err, "when load table {%s} sets", k)
		}()
		var sets []*nftlib.Set
		if sets, err = conn.GetSets(v); err != nil {
			return false
		}
		linq.From(sets).
			SkipWhile(func(_ any) bool {
				return err != nil
			}).
			ForEach(func(i any) {
				s := i.(*nftlib.Set)
				s.Table = v
				var els []nftlib.SetElement
				if els, err = conn.GetSetElements(s); err != nil {
					err = errors.WithMessagef(err, "when load elements for '%s' set", s.Name)
					return
				}
				sts := cnf.Sets.At(k)
				if !sts.Insert(s.Name, NfSet{Set: s, Elements: els}) {
					err = errors.Errorf("set '%s' is not unique", s.Name)
					return
				}
				cnf.Sets.Put(k, sts)
			})
		return err == nil
	})
	return err
}

func (cnf *NFTablesConf) loadChains(conn *nftlib.Conn) (err error) {
	const api = "nft/load-chains"
	defer func() {
		err = errors.WithMessage(err, api)
	}()
	var chains []*nftlib.Chain
	chains, err = conn.ListChains()
	linq.From(chains).
		SkipWhile(func(_ any) bool {
			return err != nil
		}).
		ForEach(func(i any) {
			chn := i.(*nftlib.Chain)
			kt := NfTableKey{TableFamily: chn.Table.Family, Name: chn.Table.Name}
			kc := NfChainKey{ChainType: chn.Type, Name: chn.Name}
			tbl := cnf.Tables.At(kt)
			if tbl == nil {
				err = errors.Errorf("table {%s} ref by chain {%s} is not found", kt, kc)
				return
			}
			defer func() {
				err = errors.WithMessagef(err, "in table {%s}", kt)
			}()
			var rls []*nftlib.Rule
			if rls, err = conn.GetRules(chn.Table, chn); err != nil {
				err = errors.WithMessagef(err, "when load chain {%s} rules", kc)
				return
			}
			chn.Table = tbl
			for _, r := range rls {
				r.Chain, r.Table = chn, tbl
			}
			c := NfChain{Chain: chn, Rules: rls}
			chains := cnf.Chains.At(kt)
			if !chains.Insert(kc, c) {
				err = errors.Errorf("chain {%s} is not unique", kc)
				return
			}
			cnf.Chains.Put(kt, chains)
		})
	return err
}
