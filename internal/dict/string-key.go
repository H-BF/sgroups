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
	if strings.EqualFold(l, r) {
		return 0
	}
	return strings.Compare(l, r)
}
