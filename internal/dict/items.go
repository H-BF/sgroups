package dict

// KV -
type KV[K any, V any] struct {
	K K
	V V
}

// Items -
type Items[K any, V any] []KV[K, V]

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
