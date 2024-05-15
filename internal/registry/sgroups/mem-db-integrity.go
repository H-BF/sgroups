package sgroups

import (
	"fmt"
	"net"

	model "github.com/H-BF/sgroups/internal/models/sgroups"

	"github.com/H-BF/corlib/pkg/dict"
	"github.com/pkg/errors"
)

// IntegrityChecker4SGRules checks SG Rules restrictions
func IntegrityChecker4SGRules() IntegrityChecker {
	const api = "Integrity-of-SGRules"

	return func(reader MemDbReader) error {
		it, err := reader.Get(TblSecRules, indexID)
		if isInvalidTableErr(err) {
			return nil
		}
		if err != nil {
			return errors.WithMessage(err, api)
		}
		if it == nil {
			return nil
		}
		for x := it.Next(); x != nil; x = it.Next() {
			r := x.(*model.SGRule)
			sgn := [...]string{r.ID.SgFrom, r.ID.SgTo}
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

// IntegrityChecker4FqdnRules checks SG Rules restrictions
func IntegrityChecker4FqdnRules() IntegrityChecker {
	const api = "Integrity-of-FqdnRules"

	return func(reader MemDbReader) error {
		it, err := reader.Get(TblFqdnRules, indexID)
		if isInvalidTableErr(err) {
			return nil
		}
		if err != nil {
			return errors.WithMessage(err, api)
		}
		if it == nil {
			return nil
		}
		for x := it.Next(); x != nil; x = it.Next() {
			r := x.(*model.FQDNRule)
			i, e := reader.First(TblSecGroups, indexID, r.ID.SgFrom)
			if e != nil {
				return errors.WithMessagef(e, "%s: find ref to SG '%s'", api, r.ID.SgFrom)
			}
			if i == nil {
				return errors.Errorf("%s: not found ref to SG '%s'", api, r.ID.SgFrom)
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
		if isInvalidTableErr(e) {
			return nil
		}
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
			for _, nwName := range sg.Networks {
				var xNw interface{}
				if xNw, e = reader.First(TblNetworks, indexID, nwName); e != nil {
					return errors.WithMessagef(e, "%s: SG '%s' get related network '%s'",
						api, sg.Name, nwName)
				}
				if xNw == nil {
					return errors.Errorf("%s: SG '%s' no related network '%s'",
						api, sg.Name, nwName)
				}
				all[kt{nw: nwName, sg: sg.Name}] = struct{}{}
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

// IntegrityChecker4Networks -
func IntegrityChecker4Networks() IntegrityChecker { //nolint:gocyclo
	const api = "Integrity-of-Networks"

	errf := func(n1, n2 *model.Network) error {
		return errors.Errorf("networks %s, %s have intersection", n1, n2)
	}

	return func(reader MemDbReader) error {
		it, e := reader.Get(TblNetworks, indexID)
		if isInvalidTableErr(e) {
			return nil
		}
		if e != nil {
			return errors.WithMessage(e, api)
		}
		type nw struct {
			interval bool
			*model.Network
		}
		var nets dict.RBDict[bigInt, nw]
		var h cidr2bigInt
		for x := it.Next(); x != nil; x = it.Next() {
			n := x.(*model.Network)
			h.init(n.Net)
			lb := h.lowerBound()
			rb := h.upperBound()
			nwk := nw{interval: lb.Cmp(rb) != 0, Network: n}
			if !nets.Insert(lb, nwk) {
				n0 := nets.At(lb)
				e = errf(n, n0.Network)
				break
			}
			if nwk.interval && !nets.Insert(rb, nwk) {
				n0 := nets.At(rb)
				e = errf(n, n0.Network)
				break
			}
		}
		if e != nil {
			return errors.WithMessage(e, api)
		}
		var prev *model.Network
		nets.Iterate(func(_ bigInt, n nw) bool {
			if prev != nil {
				if prev != n.Network {
					e = errf(prev, n.Network)
				}
				prev = nil
				return e == nil
			}
			if n.interval {
				prev = n.Network
			}
			return true
		})
		return errors.WithMessage(e, api)
	}
}

// IntegrityChecker4SgIcmpRules -
func IntegrityChecker4SgIcmpRules() IntegrityChecker {
	const api = "Integrity-of-SgIcmpRules"

	return func(reader MemDbReader) error {
		it, e := reader.Get(TblSgIcmpRules, indexID)
		if isInvalidTableErr(e) {
			return nil
		}
		if e != nil {
			return errors.WithMessage(e, api)
		}
		for x := it.Next(); x != nil; x = it.Next() {
			r := x.(*model.SgIcmpRule)
			i, e := reader.First(TblSecGroups, indexID, r.Sg)
			if e != nil {
				return errors.WithMessagef(e, "%s: find ref to SG '%s'", api, r.Sg)
			}
			if i == nil {
				return errors.Errorf("%s: not found ref to SG '%s'", api, r.Sg)
			}
		}
		return nil
	}
}

// IntegrityChecker4SgSgIcmpRules -
func IntegrityChecker4SgSgIcmpRules() IntegrityChecker {
	const api = "Integrity-of-SgSgIcmpRules"

	return func(reader MemDbReader) error {
		it, e := reader.Get(TblSgSgIcmpRules, indexID)
		if isInvalidTableErr(e) {
			return nil
		}
		if e != nil {
			return errors.WithMessage(e, api)
		}
		for x := it.Next(); x != nil; x = it.Next() {
			r := x.(*model.SgSgIcmpRule)
			for _, sg := range [...]string{r.SgFrom, r.SgTo} {
				i, e := reader.First(TblSecGroups, indexID, sg)
				if e != nil {
					return errors.WithMessagef(e, "%s: find ref to SG '%s'", api, sg)
				}
				if i == nil {
					return errors.Errorf("%s: not found ref to SG '%s'", api, sg)
				}
			}
		}
		return nil
	}
}

// IntegrityChecker4CidrSgRules -
func IntegrityChecker4CidrSgRules() IntegrityChecker { //nolint:gocyclo
	const api = "Integrity-of-CidrSgRules"

	return func(reader MemDbReader) error {
		it, e := reader.Get(TblCidrSgRules, indexSG)
		if isInvalidTableErr(e) {
			return nil
		}
		if e != nil {
			return errors.WithMessage(e, api)
		}
		for x := it.Next(); x != nil; x = it.Next() { //SG ref validate
			r := x.(*model.IECidrSgRule)
			i, e1 := reader.First(TblSecGroups, indexID, r.ID.SG)
			if e1 != nil {
				return errors.WithMessagef(e1, "%s: find ref to SG '%s'", api, r.ID.SG)
			}
			if i == nil {
				return errors.Errorf("%s: not found ref to SG '%s'", api, r.ID.SG)
			}
		}

		it, e = reader.Get(TblCidrSgRules, indexProtoSgTraffic) //detects CIDRS intersections
		if e != nil {
			return errors.WithMessage(e, api)
		}

		type gk struct {
			Transport model.NetworkTransport
			SG        string
			Traffic   model.Traffic
		}
		det := cidrsIntersectionDetector[*model.IECidrSgRule]{
			cidrExtractor: func(r *model.IECidrSgRule) net.IPNet {
				return r.ID.CIDR
			},
			errf: func(rr []*model.IECidrSgRule) (e error) {
				var ss []fmt.Stringer
				for i := range rr {
					ss = append(ss, rr[i].ID)
				}
				if len(ss) > 0 {
					e = fmt.Errorf("some 'IECidrSgRules' %s have intersected CIDRs", ss)
				}
				return e
			},
		}
		e = groupIterator[*model.IECidrSgRule, gk]{
			keyExtractor: func(r *model.IECidrSgRule) gk {
				return gk{
					Transport: r.ID.Transport,
					SG:        r.ID.SG,
					Traffic:   r.ID.Traffic,
				}
			},
		}.iterate(it, func(rr []*model.IECidrSgRule) error {
			rr2 := det.detect(rr)
			return det.errf(rr2)
		})
		return errors.WithMessage(e, api)
	}
}

// IntegrityChecker4CidrSgIcmpRules -
func IntegrityChecker4CidrSgIcmpRules() IntegrityChecker {
	const api = "Integrity-of-CidrSgIcmpRules"

	return func(reader MemDbReader) error {
		it, e := reader.Get(TblIECidrSgIcmpRules, indexID)
		if isInvalidTableErr(e) {
			return nil
		}
		if e != nil {
			return errors.WithMessage(e, api)
		}
		for x := it.Next(); x != nil; x = it.Next() { //SG ref validate
			r := x.(*model.IECidrSgIcmpRule)
			sg := r.ID().SG
			i, e1 := reader.First(TblSecGroups, indexID, sg)
			if e1 != nil {
				return errors.WithMessagef(e1, "%s: find ref to SG '%s'", api, sg)
			}
			if i == nil {
				return errors.Errorf("%s: not found ref to SG '%s'", api, sg)
			}
		}
		type gk struct {
			IPv     uint8
			SG      string
			Traffic model.Traffic
		}
		it, e = reader.Get(TblIECidrSgIcmpRules, indexIPvSgTraffic)
		if e != nil {
			return errors.WithMessage(e, api)
		}
		det := cidrsIntersectionDetector[*model.IECidrSgIcmpRule]{
			cidrExtractor: func(r *model.IECidrSgIcmpRule) net.IPNet {
				return r.CIDR
			},
			errf: func(rr []*model.IECidrSgIcmpRule) (e error) {
				var ss []fmt.Stringer
				for i := range rr {
					ss = append(ss, rr[i].ID())
				}
				if len(ss) > 0 {
					e = fmt.Errorf("some 'IECidrSgIcmpRule(s)' %s have intersected CIDRs", ss)
				}
				return e
			},
		}
		e = groupIterator[*model.IECidrSgIcmpRule, gk]{
			keyExtractor: func(r *model.IECidrSgIcmpRule) gk {
				return gk{
					IPv:     r.Icmp.IPv,
					SG:      r.SG,
					Traffic: r.Traffic,
				}
			},
		}.iterate(it, func(rr []*model.IECidrSgIcmpRule) error {
			rr2 := det.detect(rr)
			return det.errf(rr2)
		})
		return errors.WithMessage(e, api)
	}
}

// IntegrityChecker4SgSgRules - checks existence of referred SGs
func IntegrityChecker4SgSgRules() IntegrityChecker {
	const api = "Integrity-of-SgSgRules"

	return func(reader MemDbReader) error {
		it, e := reader.Get(TblSgSgRules, indexID)
		if isInvalidTableErr(e) {
			return nil
		}
		if e != nil {
			return errors.WithMessage(e, api)
		}
		for x := it.Next(); x != nil; x = it.Next() { // validate SG refs
			rule := x.(*model.IESgSgRule)
			sg, e1 := reader.First(TblSecGroups, indexID, rule.ID.SgLocal)
			if e1 != nil {
				return errors.WithMessagef(e1, "%s: find ref to SgLocal '%s'", api, rule.ID.SgLocal)
			}
			if sg == nil {
				return errors.Errorf("%s: not found ref to SgLocal '%s'", api, rule.ID.SgLocal)
			}

			sg, e1 = reader.First(TblSecGroups, indexID, rule.ID.Sg)
			if e1 != nil {
				return errors.WithMessagef(e1, "%s: find ref to Sg '%s'", api, rule.ID.Sg)
			}
			if sg == nil {
				return errors.Errorf("%s: not found ref to Sg '%s'", api, rule.ID.Sg)
			}
		}
		return nil
	}
}

// IntegrityChecker4IESgSgIcmpRules - checks existence of referred SGs
func IntegrityChecker4IESgSgIcmpRules() IntegrityChecker {
	const api = "Integrity-of-IESgSgIcmpRules"

	return func(reader MemDbReader) error {
		it, e := reader.Get(TblIESgSgIcmpRules, indexID)
		if isInvalidTableErr(e) {
			return nil
		}
		if e != nil {
			return errors.WithMessage(e, api)
		}
		for x := it.Next(); x != nil; x = it.Next() { // validate SG refs
			rule := x.(*model.IESgSgIcmpRule)
			id := rule.ID()
			sgLocal := id.SgLocal
			secGroup, e1 := reader.First(TblSecGroups, indexID, sgLocal)
			if e1 != nil {
				return errors.WithMessagef(e1, "%s: find ref to SgLocal '%s'", api, sgLocal)
			}
			if secGroup == nil {
				return errors.Errorf("%s: not found ref to SgLocal '%s'", api, sgLocal)
			}

			sg := id.Sg
			secGroup, e1 = reader.First(TblSecGroups, indexID, sg)
			if e1 != nil {
				return errors.WithMessagef(e1, "%s: find ref to Sg '%s'", api, sg)
			}
			if secGroup == nil {
				return errors.Errorf("%s: not found ref to Sg '%s'", api, sg)
			}
		}
		return nil
	}
}
