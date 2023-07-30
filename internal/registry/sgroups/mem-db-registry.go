package sgroups

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"sync/atomic"
)

type (
	emptyRegistry struct{}

	memDbRegisrtyHolder struct {
		atomic.Value
	}

	memRegistryInner struct {
		MemDB
		sync.Once
	}
)

// NewRegistryFromMemDB new Registry from MemDB
func NewRegistryFromMemDB(m MemDB) Registry {
	ret := new(memDbRegisrtyHolder)
	ret.Store(
		reflect.ValueOf(&memRegistryInner{MemDB: m}),
	)
	return ret
}

var (
	// ErrNoRegistry -
	ErrNoRegistry = errors.New("no registry available")

	// ErrWriterClosed -
	ErrWriterClosed = errors.New("writer is closed")

	// ErrReaderClosed -
	ErrReaderClosed = errors.New("reader is closed")
)

// Writer impl Registry
func (r *memDbRegisrtyHolder) Writer(_ context.Context) (Writer, error) {
	v := r.Value.Load().(reflect.Value).Interface()
	switch t := v.(type) {
	case *emptyRegistry:
		return nil, ErrNoRegistry
	case *memRegistryInner:
		return &sGroupsMemDbWriter{
			sGroupsMemDbReader: sGroupsMemDbReader{reader: t.Reader()},
			writer:             t.Writer(),
		}, nil
	default:
		panic("unexpected behavior reached")
	}
}

// Reader impl Registry
func (r *memDbRegisrtyHolder) Reader(_ context.Context) (Reader, error) {
	v := r.Value.Load().(reflect.Value).Interface()
	switch t := v.(type) {
	case *emptyRegistry:
		return nil, ErrNoRegistry
	case *memRegistryInner:
		return &sGroupsMemDbReader{
			reader: t.Reader(),
		}, nil
	default:
		panic("unexpected behavior reached")
	}
}

// Close closed db
func (r *memDbRegisrtyHolder) Close() error {
	v := r.Value.Load().(reflect.Value).Interface()
	if t, _ := v.(*memRegistryInner); t != nil {
		t.Once.Do(func() {
			r.Value.Store(reflect.ValueOf(new(emptyRegistry)))
		})
	}
	return nil
}
