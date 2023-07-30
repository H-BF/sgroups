package atomic

import (
	"testing"
)

func TestValue(t *testing.T) {
	var v Value[int32]
	v.Store(10, func(_ int32) {})
}
