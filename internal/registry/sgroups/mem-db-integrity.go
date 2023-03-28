package sgroups

import (
	"math/big"
	"sort"

	model "github.com/H-BF/sgroups/internal/models/sgroups"

	"github.com/c-robinson/iplib"
	"github.com/pkg/errors"
)

// IntegrityChecker4Rules checks SG Rules restrictions
func IntegrityChecker4Rules() IntegrityChecker {
	const api = "Integrity-of-SGRules"

	return func(reader MemDbReader) error {
		it, err := reader.Get(TblSecRules, indexID)
		if err != nil {
			return errors.WithMessage(err, api)
		}
		if it == nil {
			return nil
		}
		for x := it.Next(); x != nil; x = it.Next() {
			r := x.(*model.SGRule)
			sgn := [...]string{r.SgFrom.Name, r.SgTo.Name}
			/*//
			if sgn[0] == sgn[1] {
				return errors.Errorf("%s: 'SgFrom' and 'SgFrom' are the same as '%s'",
					api, sgn[0])
			}
			*/
			for _, n := range sgn {
				i, e := reader.First(TblSecGroups, indexID, n)
				if e != nil {
					return errors.WithMessagef(e, "%s: find ref to SG '%s'", api, n)
				}
				if i == nil {
					return errors.Errorf("%s: not found ref to SG '%s'", api, n)
				}
			}
		}

		return nil
	}
}

// IntegrityChecker4SG checks if every network belongs to only one SG
func IntegrityChecker4SG() IntegrityChecker {
	const api = "Integrity-of-SG"

	return func(reader MemDbReader) error {
		it, e := reader.Get(TblSecGroups, indexID)
		if e != nil {
			return errors.WithMessage(e, api)
		}
		if it == nil {
			return nil
		}
		type kt = struct {
			nw model.NetworkName
			sg string
		}
		type allT = map[kt]struct{}
		all := make(allT)
		for x := it.Next(); x != nil; x = it.Next() {
			sg := x.(*model.SecurityGroup)
			for _, n := range sg.Networks {
				var xNw interface{}
				if xNw, e = reader.First(TblNetworks, indexID, n.Name); e != nil {
					return errors.WithMessagef(e, "%s: SG '%s' get realeted network '%s'",
						api, sg.Name, n.Name)
				}
				if xNw == nil {
					return errors.Errorf("%s: SG '%s' no realeted network '%s'",
						api, sg.Name, n.Name)
				}
				all[kt{nw: n.Name, sg: sg.Name}] = struct{}{}
			}
		}
		counter := make(map[model.NetworkName]int)
		for k := range all {
			if counter[k.nw]++; counter[k.nw] > 1 {
				return errors.Errorf("%s: the network '%s' appears more than in one SG",
					api, k.nw)
			}
		}
		return nil
	}
}

// IntegrityChecker4Networks checks if every network does overlap another one
func IntegrityChecker4Networks() IntegrityChecker {
	const api = "Integrity-of-Networks"

	type bound struct {
		val    *big.Int
		isLeft bool
		n      *model.Network
	}
	return func(reader MemDbReader) error {
		it, e := reader.Get(TblNetworks, indexID)
		if e != nil {
			return errors.WithMessage(e, api)
		}
		var v6, v4 []bound
		for x := it.Next(); x != nil; x = it.Next() {
			n := x.(*model.Network)
			ones, _ := n.Net.Mask.Size()
			nt := iplib.NewNet(n.Net.IP, ones)
			ipF := nt.IP()
			ipL := nt.LastAddress()
			var dest *[]bound
			switch nt.Version() {
			case iplib.IP4Version:
				if ones < 31 {
					ipL = iplib.NextIP(ipL)
				}
				dest = &v4
			case iplib.IP6Version: //TODO: Check it manually
				if ones < 128 {
					ipL = iplib.NextIP(ipL)
				}
				dest = &v6
			default:
				return errors.Errorf("%s: unable detect IP version for network %s", api, n)
			}
			*dest = append(*dest, bound{
				val:    iplib.IPToBigint(ipF),
				isLeft: true,
				n:      n,
			}, bound{
				val: iplib.IPToBigint(ipL),
				n:   n,
			})
		}
		for _, bds := range [][]bound{v4, v6} {
			sort.Slice(bds, func(i, j int) bool {
				l, r := bds[i], bds[j]
				d := l.val.Cmp(r.val)
				if d != 0 {
					return d < 0
				}
				return l.isLeft && !r.isLeft
			})
			c := 0
			for i := range bds {
				b := bds[i]
				if b.isLeft {
					c++
				} else {
					c--
				}
				if (i > 0) && (c > 1 || c < 0) {
					return errors.Errorf("%s: networks %s and %s seem have overlapped region",
						api, b.n, bds[i-1].n)
				}
			}
		}
		return nil
	}
}
