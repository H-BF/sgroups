package queue

import (
	"container/list"
	"runtime"
	"sync"
	"time"
)

// NewFIFO -
func NewFIFO() *FIFO {
	ret := &FIFO{
		data:    list.New(),
		close:   make(chan struct{}),
		stopped: make(chan struct{}),
		ch:      make(chan any),
		cv:      sync.NewCond(new(sync.Mutex)),
	}
	go ret.run()
	return ret
}

// FIFO -
type FIFO struct {
	data      *list.List
	close     chan struct{}
	stopped   chan struct{}
	ch        chan any
	cv        *sync.Cond
	closeOnce sync.Once
}

// Reader -
func (que *FIFO) Reader() <-chan any {
	return que.ch
}

// Put -
func (que *FIFO) Put(v ...any) (ok bool) {
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
func (que *FIFO) Close() error {
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

func (que *FIFO) run() {
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
			case que.ch <- v:
			}
		}
	}
}

func (que *FIFO) fetch() (v any, ok bool) {
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
