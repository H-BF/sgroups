package queue

import (
	"container/list"
	"runtime"
	"sync"
	"time"
)

type FIFO[T any] interface {
	Reader() <-chan T
	Put(v ...T) bool
	Close() error
}

// NewFIFO -
func NewFIFO[T any]() *typedFIFO[T] {
	ret := &typedFIFO[T]{
		data:    list.New(),
		close:   make(chan struct{}),
		stopped: make(chan struct{}),
		ch:      make(chan T),
		cv:      sync.NewCond(new(sync.Mutex)),
	}
	go ret.run()
	return ret
}

// typedFIFO -
type typedFIFO[T any] struct {
	data      *list.List
	close     chan struct{}
	stopped   chan struct{}
	ch        chan T
	cv        *sync.Cond
	closeOnce sync.Once
}

// Reader -
func (que *typedFIFO[T]) Reader() <-chan T {
	return que.ch
}

// Put -
func (que *typedFIFO[T]) Put(v ...T) (ok bool) {
	que.cv.L.Lock()
	defer func() {
		que.cv.L.Unlock()
		if ok && len(v) > 0 {
			que.cv.Broadcast()
		}
	}()
	if que.data != nil {
		for i := range v {
			que.data.PushBack(v[i])
		}
		ok = true
	}
	return ok
}

// Close -
func (que *typedFIFO[T]) Close() error {
	stopped := que.stopped
	cv := que.cv
	cl := que.close
	que.closeOnce.Do(func() {
		const waitBeforeBroadcast = 100 * time.Millisecond
		close(cl)
		cv.L.Lock()
		que.data = nil
		cv.L.Unlock()
		for cv.Broadcast(); ; cv.Broadcast() {
			select {
			case <-stopped:
				return
			case <-time.After(waitBeforeBroadcast):
			}
		}
	})
	return nil
}

func (que *typedFIFO[T]) run() {
	defer func() {
		close(que.ch)
		close(que.stopped)
	}()
	for closed := false; !closed; {
		if v, ok := que.fetch(); !ok {
			select {
			case <-que.close:
				closed = true
			default:
				runtime.Gosched()
			}
		} else {
			select {
			case <-que.close:
				closed = true
			case que.ch <- v.(T):
			}
		}
	}
}

func (que *typedFIFO[T]) fetch() (v any, ok bool) {
	que.cv.L.Lock()
	defer que.cv.L.Unlock()
	data := que.data
	if data == nil {
		return v, false
	}
	hasData := data.Len() != 0
	if !hasData {
		que.cv.Wait()
		hasData = data.Len() != 0
	}
	if hasData {
		o := data.Front()
		v, ok = o.Value, true
		data.Remove(o)
	}
	return v, ok
}
