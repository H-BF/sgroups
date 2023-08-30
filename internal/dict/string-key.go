package dict

import (
	"strings"
)

type (
	// StringCiKey - compare no case string key
	StringCiKey string
)

// Cmp -
func (a StringCiKey) Cmp(b StringCiKey) int {
	l, r := string(a), string(b)
	return tern(strings.EqualFold(l, r),
		0, strings.Compare(l, r))
}
