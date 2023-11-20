package dict

type (
	// Dict abstact interface
	Dict[Tk any, Tv any] interface {
		Clear()
		Len() int
		Del(keys ...Tk)
		Put(k Tk, v Tv)
		Insert(k Tk, v Tv) bool
		Get(k Tk) (v Tv, ok bool)
		Keys() []Tk
		Items() Items[Tk, Tv]
		Iterate(f func(k Tk, v Tv) bool)
		At(k Tk) Tv
		Eq(other Dict[Tk, Tv], valuesEq func(vL, vR Tv) bool) bool
	}

	// KV -
	KV[K any, V any] struct {
		K K
		V V
	}

	// Items -
	Items[K any, V any] []KV[K, V]

	// Set -
	Set[T any] interface {
		Clear()
		Len() int
		Del(keys ...T)
		Put(k T)
		PutMany(vals ...T)
		Insert(k T) bool
		Contains(k T) bool
		Iterate(f func(k T) bool)
		Values() []T
		Eq(Set[T]) bool
	}
)

// Reserve -
func (i *Items[K, V]) Reserve(n int) {
	if n < 0 {
		panic("negative")
	}
	*i = make(Items[K, V], 0, n)
}

// Add -
func (i *Items[K, V]) Add(k K, v V) *Items[K, V] {
	*i = append(*i, KV[K, V]{k, v})
	return i
}
