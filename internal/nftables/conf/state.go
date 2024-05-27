//go:build linux
// +build linux

package conf

import (
	"fmt"

	hlp "github.com/H-BF/sgroups/internal/nftables/helpers"

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

// StateOfNFTables -
type StateOfNFTables struct {
	Tables  dkt.HDict[NfTableKey, *nftlib.Table]
	Sets    dkt.HDict[NfTableKey, dkt.HDict[string, NfSet]]
	Chains  dkt.HDict[NfTableKey, dkt.HDict[NfChainKey, NfChain]]
	Objects dkt.HDict[NfTableKey, []nftlib.Obj]
}

// LoadState -
func LoadState(lst Lister) (cnf StateOfNFTables, err error) {
	lds := []func(Lister) error{
		cnf.loadTables, cnf.loadSets, cnf.loadChains, cnf.loadObjects,
	}
	for i := range lds {
		if err = lds[i](lst); err != nil {
			break
		}
	}
	return cnf, err
}

// String -
func (k NfTableKey) String() string {
	return fmt.Sprintf("'%s'/%s", k.Name, hlp.TableFamily2S(k.TableFamily))
}

// String -
func (k NfChainKey) String() string {
	return fmt.Sprintf("'%s'/'%s'", k.Name, k.ChainType)
}

func (cnf *StateOfNFTables) loadTables(lst Lister) (err error) {
	const api = "nft-conf/load-tables"
	defer func() {
		err = errors.WithMessage(err, api)
	}()
	var tbs []*nftlib.Table
	if tbs, err = lst.ListTables(); err != nil {
		return err
	}
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

func (cnf *StateOfNFTables) loadSets(lst Lister) (err error) {
	const api = "nft-conf/load-sets"
	defer func() {
		err = errors.WithMessage(err, api)
	}()
	cnf.Tables.Iterate(func(k NfTableKey, v *nftlib.Table) bool {
		defer func() {
			err = errors.WithMessagef(err, "when load table {%s} sets", k)
		}()
		var sets []*nftlib.Set
		if sets, err = lst.GetSets(v); err != nil {
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
				if els, err = lst.GetSetElements(s); err != nil {
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

func (cnf *StateOfNFTables) loadChains(lst Lister) (err error) {
	const api = "nft-conf/load-chains"
	defer func() {
		err = errors.WithMessage(err, api)
	}()
	var chains []*nftlib.Chain
	if chains, err = lst.ListChains(); err != nil {
		return err
	}
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
			if rls, err = lst.GetRules(chn); err != nil {
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

func (cnf *StateOfNFTables) loadObjects(lst Lister) (err error) {
	const api = "nft-conf/objects-objects"
	defer func() {
		err = errors.WithMessage(err, api)
	}()
	cnf.Tables.Iterate(func(k NfTableKey, v *nftlib.Table) bool {
		defer func() {
			err = errors.WithMessagef(err, "when load table {%s} objects", k)
		}()
		var objs []nftlib.Obj
		if objs, err = lst.GetObjects(v); err == nil && len(objs) > 0 {
			cnf.Objects.Put(k, objs)
		}
		return err == nil
	})
	return err
}
