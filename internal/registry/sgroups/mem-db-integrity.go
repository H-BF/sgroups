package sgroups

import (
	"github.com/H-BF/sgroups/internal/dict"
	model "github.com/H-BF/sgroups/internal/models/sgroups"

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

/*//TODO: remove this
func IntegrityChecker4Networks2() IntegrityChecker { //nolint:gocyclo
	const api = "Integrity-of-Networks"

	type bound struct {
		val    bigInt
		isLeft bool
		n      *model.Network
	}
	return func(reader MemDbReader) error {
		it, e := reader.Get(TblNetworks, indexID)
		if isInvalidTableErr(e) {
			return nil
		}
		if e != nil {
			return errors.WithMessage(e, api)
		}
		var bounds []bound
		for x := it.Next(); x != nil; x = it.Next() {
			n := x.(*model.Network)
			var h cidr2bigInt
			h.init(n.Net)
			bounds = append(bounds,
				bound{
					isLeft: true,
					n:      n,
					val:    h.lowerBound(),
				})
			bounds = append(bounds,
				bound{
					n:   n,
					val: h.upperBound(),
				})
		}
		sort.Slice(bounds, func(i, j int) bool {
			l, r := bounds[i], bounds[j]
			d := l.val.Cmp(r.val)
			if d != 0 {
				return d < 0
			}
			return l.isLeft && !r.isLeft
		})
		c := 0
		for i := range bounds {
			b := bounds[i]
			if b.isLeft {
				c++
			} else {
				c--
			}
			if (i > 0) && (c > 1 || c < 0) {
				return errors.Errorf("%s: networks %s, %s have overlapped region",
					api, b.n, bounds[i-1].n)
			}
		}
		return nil
	}
}
*/

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

// IntegrityChecker4SgIcmpRules -
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

	errf := func(objs ...model.CidrSgRuleIdenity) error {
		if len(objs) <= 1 {
			return nil
		}
		return errors.Errorf("some rules %s have CIDRS with intersected segments", objs)
	}
	detectCidrsIntersections := func(objs []model.CidrSgRuleIdenity) error {
		type ref struct {
			i        int
			interval bool
		}
		if len(objs) < 2 {
			return nil
		}
		var refs dict.RBDict[bigInt, ref]
		var h cidr2bigInt
		for i := range objs {
			r := &objs[i]
			h.init(r.CIDR)
			lb, rb := h.lowerBound(), h.upperBound()
			rf := ref{i: i, interval: lb.Cmp(rb) != 0}
			if !refs.Insert(lb, rf) {
				x := refs.At(lb)
				return errf(*r, objs[x.i])
			}
			if rf.interval && !refs.Insert(rb, rf) {
				x := refs.At(rb)
				return errf(*r, objs[x.i])
			}
		}
		var e error
		prevRef := -1
		refs.Iterate(func(_ bigInt, rf ref) bool {
			if prevRef >= 0 {
				if prevRef != rf.i {
					e = errf(objs[prevRef], objs[rf.i])
				}
				prevRef = -1
				return e == nil
			}
			if rf.interval {
				prevRef = rf.i
			}
			return true
		})
		return e
	}

	return func(reader MemDbReader) error {
		it, e := reader.Get(TblCidrSgRules, indexSG)
		if isInvalidTableErr(e) {
			return nil
		}
		if e != nil {
			return errors.WithMessage(e, api)
		}
		for x := it.Next(); x != nil; x = it.Next() { //SG ref validate
			r := x.(*model.CidrSgRule)
			i, e1 := reader.First(TblSecGroups, indexID, r.ID.SG)
			if e1 != nil {
				return errors.WithMessagef(e1, "%s: find ref to SG '%s'", api, r.ID.SG)
			}
			if i == nil {
				return errors.Errorf("%s: not found ref to SG '%s'", api, r.ID.SG)
			}
		}

		type groupKey struct {
			Transport model.NetworkTransport
			SG        string
			Traffic   model.Traffic
		}
		it, e = reader.Get(TblCidrSgRules, indexProtoSgTraffic) //detects CIDRS intersections
		if e != nil {
			return errors.WithMessage(e, api)
		}
		var objs []model.CidrSgRuleIdenity
		var prevKey groupKey
		for x := it.Next(); x != nil; x = it.Next() {
			r := x.(*model.CidrSgRule)
			k := groupKey{
				Transport: r.ID.Transport,
				SG:        r.ID.SG,
				Traffic:   r.ID.Traffic,
			}
		loop:
			if len(objs) == 0 {
				prevKey = k
				objs = append(objs, r.ID)
			} else if prevKey == k {
				objs = append(objs, r.ID)
			} else {
				if err := detectCidrsIntersections(objs); err != nil {
					return errors.WithMessage(err, api)
				}
				objs = objs[:0]
				goto loop
			}
		}
		err := detectCidrsIntersections(objs)
		return errors.WithMessage(err, api)
	}
}
