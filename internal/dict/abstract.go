package dict

import "golang.org/x/exp/constraints"

// CmpOps -
type CmpOps[T any] interface {
	Cmp(T) int
}

type explicitComparer[T any] struct {
	CmpOps[T]
}

// Value -
func (c explicitComparer[T]) Value() T {
	return c.CmpOps.(T)
}

type rbKeyType[T any] interface {
	constraints.Ordered | explicitComparer[T]
}
