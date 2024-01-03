package config

import (
	"fmt"
)

// OneOf -
type OneOf[T any] interface {
	Variants() []T
	Eq(T) bool
}

func validateOneOf[T any](arg OneOf[T]) error {
	va := arg.Variants()
	if len(va) == 0 {
		panic(
			fmt.Errorf("no any variant is defined for %T", arg),
		)
	}
	for _, v := range va {
		if arg.Eq(v) {
			return nil
		}
	}
	return fmt.Errorf("%v is not in %v", arg, va)
}
