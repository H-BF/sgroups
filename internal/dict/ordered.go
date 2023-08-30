package dict

import (
	"reflect"

	"golang.org/x/exp/constraints"
)

func tern[T any](cond bool, a, b T) T {
	if cond {
		return a
	}
	return b
}

func extractOrdered[R constraints.Ordered](v any) R {
	tyRet := reflect.ValueOf((*R)(nil)).Type().Elem()
	var ret R
	reflect.ValueOf(&ret).Elem().Set(
		reflect.ValueOf(v).Convert(tyRet),
	)
	return ret
}

func orderedCmp[Arg any]() func(any, any) int {
	ty := reflect.ValueOf((*Arg)(nil)).Type().Elem()
	switch ty.Kind() {
	case reflect.String:
		return func(a1, a2 any) int {
			l, r := extractOrdered[string](a1), extractOrdered[string](a2)
			return tern(l < r, -1, tern(l == r, 0, 1))
		}
	case reflect.Int:
		return func(a1, a2 any) int {
			l, r := extractOrdered[int](a1), extractOrdered[int](a2)
			return tern(l < r, -1, tern(l == r, 0, 1))
		}
	case reflect.Int8:
		return func(a1, a2 any) int {
			l, r := extractOrdered[int8](a1), extractOrdered[int8](a2)
			return tern(l < r, -1, tern(l == r, 0, 1))
		}
	case reflect.Int16:
		return func(a1, a2 any) int {
			l, r := extractOrdered[int16](a1), extractOrdered[int16](a2)
			return tern(l < r, -1, tern(l == r, 0, 1))
		}
	case reflect.Int32:
		return func(a1, a2 any) int {
			l, r := extractOrdered[int32](a1), extractOrdered[int32](a2)
			return tern(l < r, -1, tern(l == r, 0, 1))
		}
	case reflect.Int64:
		return func(a1, a2 any) int {
			l, r := extractOrdered[int64](a1), extractOrdered[int64](a2)
			return tern(l < r, -1, tern(l == r, 0, 1))
		}
	case reflect.Uint:
		return func(a1, a2 any) int {
			l, r := extractOrdered[uint](a1), extractOrdered[uint](a2)
			return tern(l < r, -1, tern(l == r, 0, 1))
		}
	case reflect.Uint8:
		return func(a1, a2 any) int {
			l, r := extractOrdered[uint8](a1), extractOrdered[uint8](a2)
			return tern(l < r, -1, tern(l == r, 0, 1))
		}
	case reflect.Uint16:
		return func(a1, a2 any) int {
			l, r := extractOrdered[uint16](a1), extractOrdered[uint16](a2)
			return tern(l < r, -1, tern(l == r, 0, 1))
		}
	case reflect.Uint32:
		return func(a1, a2 any) int {
			l, r := extractOrdered[uint32](a1), extractOrdered[uint32](a2)
			return tern(l < r, -1, tern(l == r, 0, 1))
		}
	case reflect.Uint64:
		return func(a1, a2 any) int {
			l, r := extractOrdered[uint64](a1), extractOrdered[uint64](a2)
			return tern(l < r, -1, tern(l == r, 0, 1))
		}
	case reflect.Uintptr:
		return func(a1, a2 any) int {
			l, r := extractOrdered[uintptr](a1), extractOrdered[uintptr](a2)
			return tern(l < r, -1, tern(l == r, 0, 1))
		}
	case reflect.Float32:
		return func(a1, a2 any) int {
			l, r := extractOrdered[float32](a1), extractOrdered[float32](a2)
			return tern(l < r, -1, tern(l == r, 0, 1))
		}
	case reflect.Float64:
		return func(a1, a2 any) int {
			l, r := extractOrdered[float64](a1), extractOrdered[float64](a2)
			return tern(l < r, -1, tern(l == r, 0, 1))
		}
	}
	return nil
}
