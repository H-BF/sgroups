package dict

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_Set(t *testing.T) {
	var h HSet[int]
	var r RBSet[int]
	n := h.Len()
	require.Equal(t, 0, n)
	n = r.Len()
	require.Equal(t, 0, n)

	h.Put(1)
	h.Put(2)
	h.Put(3)
	n = h.Len()
	require.Equal(t, 3, n)

	r.Put(1)
	r.Put(2)
	r.Put(3)
	n = r.Len()
	require.Equal(t, 3, n)

	eq := r.Eq(&h)
	require.True(t, eq)
	eq = h.Eq(&r)
	require.True(t, eq)

	h.Del(1)
	n = h.Len()
	require.Equal(t, 2, n)

	r.Del(1)
	n = r.Len()
	require.Equal(t, 2, n)

	h.Clear()
	n = h.Len()
	require.Equal(t, 0, n)

	r.Clear()
	n = r.Len()
	require.Equal(t, 0, n)

	r.Put(11)
	r.Put(12)
	r.Put(13)
	r.Iterate(h.Insert)
	eq = r.Eq(&h)
	require.True(t, eq)

	var r1 RBSet[StringCiKey]
	ss := []StringCiKey{"aaa", "aAa", "Aaa"}
	for i := range ss {
		r1.Insert(ss[i])
	}
	n = r1.Len()
	require.Equal(t, 1, n)
	for i := range ss {
		ok := r1.Contains(ss[i])
		require.True(t, ok)
	}
}

func Test_RBDict(t *testing.T) {
	var di RBDict[StringCiKey, int]
	di.Insert("aaa", 1)
	di.Insert("aAa", 2)
	di.Insert("aAA", 3)
	di.Insert("aa1a", 100)
	require.Equal(t, 2, di.Len())
	require.Equal(t,
		*(&Items[StringCiKey, int]{}).Add("aa1a", 100).Add("aaa", 1),
		di.Items(),
	)

	di2 := RBDict[string, int]{}
	di2.Put("aaa", 1)
	di2.Put("aAa", 2)
	di2.Put("aAA", 3)
	require.Equal(t, 3, di2.Len())
	require.Equal(t,
		*(&Items[string, int]{}).Add("aAA", 3).Add("aAa", 2).Add("aaa", 1),
		di2.Items(),
	)
}
