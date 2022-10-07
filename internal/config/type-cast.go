package config

import (
	"reflect"
	"time"

	"github.com/H-BF/corlib/pkg/functional"
	"github.com/pkg/errors"
	"github.com/spf13/cast"
	"go.uber.org/multierr"
)

//KnownValueTypes ...
type KnownValueTypes interface {
	time.Time |

		~int | ~uint |
		~int64 | ~uint64 |
		~int32 | ~uint32 |
		~int16 | ~uint16 |
		~int8 | ~uint8 |
		~float32 | ~float64 |
		~string | ~bool
}

func typeCast[T any](in any, ret *T) error {
	var c typeCastFunc[T]
	err := c.load()
	if err == nil {
		*ret, err = c(in)
	}
	return err
}

type typeCastFunc[T any] func(any) (T, error)

func (f *typeCastFunc[T]) load() error {
	tyDest := reflect.TypeOf((*T)(nil)).Elem()
	kindDest := tyDest.Kind()
	if kindDest == reflect.Interface {
		*f = func(in any) (r T, e error) {
			reflect.ValueOf(&r).Elem().
				Set(reflect.ValueOf(in))
			return
		}
		return nil
	}
	castInvoker, ok := typeCastInvokers[tyDest]
	if !ok {
		for t, v := range typeCastInvokers {
			ok = t.ConvertibleTo(tyDest) &&
				kindDest == t.Kind()
			if ok {
				castInvoker = v
				break
			}
		}
		if castInvoker == nil {
			return errors.WithMessagef(ErrTypeCastNotSupported, "for-type('%s')", tyDest)
		}
	}
	*f = func(in any) (T, error) {
		var v interface{}
		var ret T
		var e error
		if e1 := castInvoker.InvokeNoResult(in, &v, &e); e1 != nil || e != nil {
			return ret, multierr.Combine(e1, e)
		}
		reflect.
			ValueOf(&ret).Elem().
			Set(
				reflect.ValueOf(v).Convert(tyDest),
			)
		return ret, nil
	}
	return nil
}

var (
	typeCastInvokers = make(map[reflect.Type]functional.Callable)
)

func constructTypeCastInvoker[T KnownValueTypes](c typeCastFunc[T]) functional.Callable {
	return functional.MustCallableOf(
		func(in interface{}, ret *interface{}, err *error) {
			*ret, *err = c(in)
		},
	)
}

func regTypeCastFunc[T KnownValueTypes](c typeCastFunc[T]) {
	var a *T
	ty := reflect.TypeOf(a).Elem()
	if typeCastInvokers[ty] != nil {
		panic(errors.Errorf("('%v') type cast is always registered", ty))
	}
	typeCastInvokers[ty] = constructTypeCastInvoker(c)
}

func init() {
	regTypeCastFunc(cast.ToBoolE)

	regTypeCastFunc(cast.ToInt8E)
	regTypeCastFunc(cast.ToInt16E)
	regTypeCastFunc(cast.ToInt32E)
	regTypeCastFunc(cast.ToInt64E)

	regTypeCastFunc(cast.ToUint8E)
	regTypeCastFunc(cast.ToUint16E)
	regTypeCastFunc(cast.ToUint32E)
	regTypeCastFunc(cast.ToUint64E)

	regTypeCastFunc(cast.ToIntE)
	regTypeCastFunc(cast.ToUintE)

	regTypeCastFunc(cast.ToStringE)

	regTypeCastFunc(cast.ToFloat32E)
	regTypeCastFunc(cast.ToFloat64E)

	regTypeCastFunc(cast.ToDurationE)
	regTypeCastFunc(cast.ToTimeE)

}
