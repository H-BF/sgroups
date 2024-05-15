package sgroups

import (
	"net"

	"github.com/H-BF/corlib/pkg/dict"
	"github.com/hashicorp/go-memdb"
)

type cidrsIntersectionDetector[T any] struct {
	cidrExtractor func(T) net.IPNet
	errf          func([]T) error
}

func (d cidrsIntersectionDetector[T]) detect(objs []T) (ret []T) {
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
		r := objs[i]
		h.init(d.cidrExtractor(r))
		lb, rb := h.lowerBound(), h.upperBound()
		rf := ref{i: i, interval: lb.Cmp(rb) != 0}
		if !refs.Insert(lb, rf) {
			x := refs.At(lb)
			return []T{r, objs[x.i]}
		}
		if rf.interval && !refs.Insert(rb, rf) {
			x := refs.At(rb)
			return []T{r, objs[x.i]}
		}
	}
	prevRef := -1
	refs.Iterate(func(_ bigInt, rf ref) bool {
		if prevRef >= 0 {
			if prevRef != rf.i {
				ret = append(ret, objs[prevRef], objs[rf.i])
				return false
			}
			prevRef = -1
			return true
		}
		if rf.interval {
			prevRef = rf.i
		}
		return true
	})
	return ret
}

type groupIterator[T any, GK comparable] struct {
	keyExtractor func(T) GK
}

func (gi groupIterator[T, GK]) iterate(i memdb.ResultIterator, consume func([]T) error) error {
	var objs []T
	var prevKey GK
	for v := i.Next(); v != nil; v = i.Next() {
		obj := v.(T)
		k := gi.keyExtractor(obj)
	loop:
		if len(objs) == 0 {
			prevKey = k
			objs = append(objs, obj)
		} else if prevKey == k {
			objs = append(objs, obj)
		} else {
			if err := consume(objs); err != nil {
				return err
			}
			objs = objs[:0]
			goto loop
		}
	}
	if len(objs) > 0 {
		return consume(objs)
	}
	return nil
}
