package dict

type (
	HSet[T comparable] struct {
		impSet[T, hDictFactory[T, struct{}]]
	}

	RBSet[T any] struct {
		impSet[T, rbDictFactory[T, struct{}]]
	}

	factoryOfDict[Tk any, Tv any] interface {
		construct() Dict[Tk, Tv]
	}

	rbDictFactory[Tk any, Tv any] struct{} //nolint:unused

	hDictFactory[Tk comparable, Tv any] struct{} //nolint:unused
)

func (rbDictFactory[Tk, Tv]) construct() Dict[Tk, Tv] { //nolint:unused
	return new(RBDict[Tk, Tv])
}

func (hDictFactory[Tk, Tv]) construct() Dict[Tk, Tv] { //nolint:unused
	return new(HDict[Tk, Tv])
}

type impSet[T any, F factoryOfDict[T, struct{}]] struct {
	Dict[T, struct{}]
}

func (set *impSet[T, F]) init() {
	if set.Dict == nil {
		var f F
		set.Dict = f.construct()
	}
}

// Clear -
func (set *impSet[T, F]) Clear() {
	set.init()
	set.Dict.Clear()
}

// Len -
func (set *impSet[T, F]) Len() int {
	set.init()
	return set.Dict.Len()
}

// Del -
func (set *impSet[T, F]) Del(keys ...T) {
	set.init()
	set.Dict.Del(keys...)
}

// Put -
func (set *impSet[T, F]) Put(k T) {
	set.init()
	set.Dict.Put(k, struct{}{})
}

// PutMany -
func (set *impSet[T, F]) PutMany(vals ...T) {
	if len(vals) > 0 {
		set.init()
		for _, k := range vals {
			set.Dict.Put(k, struct{}{})
		}
	}
}

// Insert -
func (set *impSet[T, F]) Insert(k T) bool {
	set.init()
	return set.Dict.Insert(k, struct{}{})
}

// Contains -
func (set *impSet[T, F]) Contains(k T) bool {
	set.init()
	_, ok := set.Dict.Get(k)
	return ok
}

// Iterate -
func (set *impSet[T, F]) Iterate(f func(k T) bool) {
	set.init()
	set.Dict.Iterate(func(k T, _ struct{}) bool {
		return f(k)
	})
}

// Values -
func (set *impSet[T, F]) Values() []T {
	ret := make([]T, 0, set.Len())
	set.Iterate(func(k T) bool {
		ret = append(ret, k)
		return true
	})
	return ret
}

// Eq -
func (set *impSet[T, F]) Eq(other Set[T]) bool {
	if set.Len() != other.Len() {
		return false
	}
	n := 0
	set.Iterate(func(k T) bool {
		ok := other.Contains(k)
		n += tern(ok, 1, 0)
		return ok
	})
	return n == set.Len()
}
