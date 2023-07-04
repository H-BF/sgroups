package config

import (
	"context"

	"github.com/pkg/errors"
)

var (
	//ErrTypeCastNotSupported type cast is not supported
	ErrTypeCastNotSupported = errors.New("type cast not supported")

	//ErrNotFound value is not found
	ErrNotFound = errors.New("value not found")
)

// ValueOpt ...
type ValueOpt[T any] interface {
	privateValueOpt()
}

// Defaulter ...
type Defaulter[T any] struct {
	ValueOpt[T]
	Def func() (T, error)
}

// Sink ...
type Sink[T any] struct {
	ValueOpt[T]
	In func(T) error
}

// Value config value interface
type Value[T any] interface {
	String() string
	MustValue(ctx context.Context, opts ...ValueOpt[T]) T
	Value(ctx context.Context, opts ...ValueOpt[T]) (T, error)
}
