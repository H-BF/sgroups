package config

import (
	"context"

	"github.com/H-BF/corlib/logger"
	"github.com/pkg/errors"
)

type (
	//ValueT typed value accessor
	ValueT[T any] string
)

var _ Value[int] = (*ValueT[int])(nil)

// String2ValueT ...
func String2ValueT[T any](s string) ValueT[T] {
	return ValueT[T](s)
}

// OptDefaulter ...
func (v ValueT[T]) OptDefaulter(f func() (T, error)) ValueOpt[T] {
	return Defaulter[T]{Def: f}
}

// OptSink ...
func (v ValueT[T]) OptSink(f func(T) error) ValueOpt[T] {
	return Sink[T]{In: f}
}

// String stringer impl
func (v ValueT[T]) String() string {
	return string(v)
}

// MustValue gets value or panics
func (v ValueT[T]) MustValue(ctx context.Context, opts ...ValueOpt[T]) T {
	ret, err := v.Value(ctx, opts...)
	if err != nil {
		logger.Fatal(ctx, err)
	}
	return ret
}

// Value ...
func (v ValueT[T]) Value(_ context.Context, opts ...ValueOpt[T]) (ret T, err error) {
	const api = "config/Value"

	defer func() {
		err = errors.WithMessagef(err, "%s: key '%v'", api, v)
	}()

	var (
		sinkIn []func(T) error
		def    func() (T, error)
	)

	for _, o := range opts {
		switch t := o.(type) {
		case Defaulter[T]:
			def = t.Def
		case Sink[T]:
			if t.In != nil {
				sinkIn = append(sinkIn, t.In)
			}
		}
	}

	raw := configStore().Get(v.String())
	if raw != nil {
		err = typeCast(raw, &ret)
	} else if def == nil {
		err = ErrNotFound
	} else {
		ret, err = def()
	}
	if err != nil {
		return ret, err
	}
	for _, s := range sinkIn {
		if err = s(ret); err != nil {
			return ret, err
		}
	}
	switch ty := any(ret).(type) {
	case OneOf[T]:
		err = validateOneOf(ty)
	case interface{ Validate() error }:
		err = ty.Validate()
	}
	return ret, err
}
