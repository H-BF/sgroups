package option

import (
	"fmt"
)

// ValueOf optional value holder
type ValueOf[T any] struct {
	v    T
	some bool
}

// IsNone -
func (val *ValueOf[_]) IsNone() bool {
	return !val.some
}

// Unset -
func (val *ValueOf[T]) Unset() {
	var o T
	val.v, val.some = o, false
}

// Set -
func (val *ValueOf[T]) Set(v T) {
	val.v, val.some = v, true
}

// Maybe -
func (val *ValueOf[T]) Maybe() (T, bool) {
	return val.v, val.some
}

// SomeOr -
func (val *ValueOf[T]) SomeOr(defVal T) T {
	if val.some {
		return val.v
	}
	return defVal
}

// IsEq -
func (val *ValueOf[T]) IsEq(other ValueOf[T], eqfT func(a, b T) bool) bool {
	if val.some == other.some {
		if val.some {
			return eqfT(val.v, other.v)
		}
		return true
	}
	return false
}

// String - fmt.Stringer
func (val ValueOf[T]) String() string {
	if !val.some {
		return "none"
	}
	return fmt.Sprintf("%v", val.v)
}
