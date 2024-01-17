package dict

import (
	rbt "github.com/emirpasic/gods/trees/redblacktree"
	"github.com/emirpasic/gods/utils"
)

// RBDict red-black tree; type key 'Tk' should be Ordered or cmpOps[Tk] interface
type RBDict[Tk any, Tv any] struct {
	m  *rbt.Tree
	cm utils.Comparator
}

type cmpOps[T any] interface {
	Cmp(T) int
}

func (dict *RBDict[Tk, Tv]) ensureInit() {
	if dict.m == nil {
		if dict.cm == nil {
			var cm utils.Comparator
			var k Tk
			switch any(k).(type) {
			case cmpOps[Tk]:
				cm = func(a, b any) int {
					return a.(cmpOps[Tk]).Cmp(b.(Tk))
				}
			default:
				if cm = orderedCmp[Tk](); cm == nil {
					panic("unable to determine key comparator")
				}
			}
			dict.cm = cm
		}
		dict.m = rbt.NewWith(dict.cm)
	}
}

// Clear -
func (dict *RBDict[Tk, Tv]) Clear() {
	dict.m = nil
}

// Len -
func (dict *RBDict[Tk, Tv]) Len() int {
	if dict.m == nil {
		return 0
	}
	return dict.m.Size()
}

// Del -
func (dict *RBDict[Tk, Tv]) Del(keys ...Tk) {
	if dict.m != nil {
		for _, k := range keys {
			dict.m.Remove(k)
		}
	}
}

// Put -
func (dict *RBDict[Tk, Tv]) Put(k Tk, v Tv) {
	dict.ensureInit()
	dict.m.Put(k, v)
}

// Insert -
func (dict *RBDict[Tk, Tv]) Insert(k Tk, v Tv) bool {
	dict.ensureInit()
	if dict.m.GetNode(k) == nil {
		dict.m.Put(k, v)
		return true
	}
	return false
}

// Get -
func (dict *RBDict[Tk, Tv]) Get(k Tk) (v Tv, ok bool) {
	if dict.m != nil {
		var x any
		if x, ok = dict.m.Get(k); ok {
			v = x.(Tv)
		}
	}
	return v, ok
}

// Keys -
func (dict *RBDict[Tk, Tv]) Keys() []Tk {
	ret := make([]Tk, 0, dict.Len())
	dict.Iterate(func(k Tk, _ Tv) bool {
		ret = append(ret, k)
		return true
	})
	return ret
}

// Items -
func (dict *RBDict[Tk, Tv]) Items() Items[Tk, Tv] {
	var ret Items[Tk, Tv]
	ret.Reserve(dict.Len())
	dict.Iterate(func(k Tk, v Tv) bool {
		ret.Add(k, v)
		return true
	})
	return ret
}

// Iterate -
func (dict *RBDict[Tk, Tv]) Iterate(f func(k Tk, v Tv) bool) {
	if dict.m != nil {
		for it := dict.m.Iterator(); it.Next(); {
			k, v := it.Key().(Tk),
				it.Value().(Tv)
			if !f(k, v) {
				return
			}
		}
	}
}

// At -
func (dict *RBDict[Tk, Tv]) At(k Tk) Tv {
	v, _ := dict.Get(k)
	return v
}

// Eq -
func (dict *RBDict[Tk, Tv]) Eq(other Dict[Tk, Tv], valuesEq func(vL, vR Tv) bool) bool {
	if dict.Len() != other.Len() {
		return false
	}
	n := 0
	dict.Iterate(func(k Tk, v Tv) bool {
		v1, ok := other.Get(k)
		eq := ok && valuesEq(v, v1)
		n += tern(eq, 1, 0)
		return eq
	})
	return n == dict.Len()
}
