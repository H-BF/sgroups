package sgroups

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"sync/atomic"

	"github.com/H-BF/sgroups/internal/patterns"
)

type (
	emptyRegistry struct{}

	memDbRegisrtyHolder struct {
		subject patterns.Subject
		atomic.Value
	}

	memRegistryInner struct {
		MemDB
		sync.Once
	}
)

// NewRegistryFromMemDB new Registry from MemDB
func NewRegistryFromMemDB(m MemDB) Registry {
	ret := &memDbRegisrtyHolder{
		subject: patterns.NewSubject(),
	}
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

// Subject  -
func (r *memDbRegisrtyHolder) Subject() patterns.Subject {
	return r.subject
}

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
			subject:            r.Subject(),
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
	_ = r.subject.Close()
	v := r.Value.Load().(reflect.Value).Interface()
	if t, _ := v.(*memRegistryInner); t != nil {
		t.Once.Do(func() {
			r.Value.Store(reflect.ValueOf(new(emptyRegistry)))
		})
	}
	return nil
}
