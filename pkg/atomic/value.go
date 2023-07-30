package atomic

import (
	"sync"
	"sync/atomic"
)

// Value is an atomic of absract value
type Value[T any] struct {
	n int32
	o *T
	_ sync.Mutex
}

// Clear it cleans value if it exists
func (c *Value[T]) Clear(cleaner func(T)) {
	for {
		if atomic.CompareAndSwapInt32(&c.n, 0, 1) {
			if c.o == nil {
				atomic.StoreInt32(&c.n, 0)
			} else {
				prev := c.o
				c.o = nil
				atomic.StoreInt32(&c.n, 0)
				if prev != nil && cleaner != nil {
					cleaner(*prev)
				}
			}
			return
		}
	}
}

// Load -
func (c *Value[T]) Load() (v T, ok bool) {
	for {
		if atomic.CompareAndSwapInt32(&c.n, 0, 1) {
			if c.o != nil {
				ok, v = true, *c.o
			}
			atomic.StoreInt32(&c.n, 0)
			return v, ok
		}
	}
}

// Fetch call sink if value is present
func (c *Value[T]) Fetch(sink func(T)) bool {
	for {
		if atomic.CompareAndSwapInt32(&c.n, 0, 1) {
			v := c.o
			atomic.StoreInt32(&c.n, 0)
			if v != nil && sink != nil {
				sink(*v)
			}
			return v != nil
		}
	}
}

// Store -
func (c *Value[T]) Store(v T, cleaner func(T)) {
	for {
		if atomic.CompareAndSwapInt32(&c.n, 0, 1) {
			prev := c.o
			c.o = &v
			atomic.StoreInt32(&c.n, 0)
			if prev != nil && cleaner != nil {
				cleaner(*prev)
			}
			return
		}
	}
}
