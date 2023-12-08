package dict

import (
	"github.com/ahmetb/go-linq/v3"
)

// HDict hashed dictionary
type HDict[Tk comparable, Tv any] struct {
	hmap[Tk, Tv]
}

type hmap[Tk comparable, Tv any] map[Tk]Tv

func (dict *HDict[Tk, Tv]) ensureInit() {
	if dict.hmap == nil {
		dict.hmap = make(hmap[Tk, Tv])
	}
}

// Clear -
func (dict *HDict[Tk, Tv]) Clear() {
	dict.hmap = nil
}

// Len -
func (dict *HDict[Tk, Tv]) Len() int {
	return len(dict.hmap)
}

// Del -
func (dict *HDict[Tk, Tv]) Del(keys ...Tk) {
	if dict.hmap != nil {
		for _, k := range keys {
			delete(dict.hmap, k)
		}
	}
}

// Put -
func (dict *HDict[Tk, Tv]) Put(k Tk, v Tv) {
	dict.ensureInit()
	dict.hmap[k] = v
}

// Insert -
func (dict *HDict[Tk, Tv]) Insert(k Tk, v Tv) bool {
	dict.ensureInit()
	if _, ok := dict.hmap[k]; !ok {
		dict.hmap[k] = v
		return true
	}
	return false
}

// Get -
func (dict *HDict[Tk, Tv]) Get(k Tk) (v Tv, ok bool) {
	if dict.hmap != nil {
		v, ok = dict.hmap[k]
	}
	return v, ok
}

// At -
func (dict *HDict[Tk, Tv]) At(k Tk) Tv {
	v, _ := dict.Get(k)
	return v
}

// Keys -
func (dict *HDict[Tk, Tv]) Keys() []Tk {
	ret := make([]Tk, 0, dict.Len())
	if dict.hmap != nil {
		linq.From(dict.hmap).ForEach(func(i any) {
			kv := i.(linq.KeyValue)
			ret = append(ret, kv.Key.(Tk))
		})
	}
	return ret
}

// Items -
func (dict *HDict[Tk, Tv]) Items() Items[Tk, Tv] {
	var ret Items[Tk, Tv]
	ret.Reserve(dict.Len())
	linq.From(dict.hmap).ForEach(func(i any) {
		kv := i.(linq.KeyValue)
		ret.Add(kv.Key.(Tk), kv.Value.(Tv))
	})
	return ret
}

// Iterate -
func (dict *HDict[Tk, Tv]) Iterate(f func(k Tk, v Tv) bool) {
	if dict.hmap != nil {
		cont := true
		linq.From(dict.hmap).
			Where(func(_ any) bool {
				return cont
			}).
			ForEach(func(i any) {
				kv := i.(linq.KeyValue)
				cont = f(kv.Key.(Tk), kv.Value.(Tv))
			})
	}
}

// Eq -
func (dict *HDict[Tk, Tv]) Eq(other Dict[Tk, Tv], valuesEq func(vL, vR Tv) bool) bool {
	if dict.Len() != other.Len() {
		return false
	}
	n := 0
	dict.Iterate(func(k Tk, v Tv) bool {
		v1, ok := other.Get(k)
		if !ok {
			return false
		}
		eq := valuesEq(v, v1)
		n += tern(eq, 1, 0)
		return eq
	})
	return n == dict.Len()
}
