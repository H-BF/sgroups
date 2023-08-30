package dict

import (
	"testing"

	"github.com/stretchr/testify/require"
)

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
