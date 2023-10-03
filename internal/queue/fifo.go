package queue

import (
	"container/list"
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
func (que *FIFO) Put(v ...any) bool {
	que.cv.L.Lock()
	ok := que.data != nil
	defer func() {
		que.cv.L.Unlock()
		if ok && len(v) > 0 {
			que.cv.Broadcast()
		}
	}()
	if ok {
		for i := range v {
			que.data.PushBack(v[i])
		}
	}
	return ok
}

// Close -
func (que *FIFO) Close() error {
	var doClose bool
	stopped := que.stopped
	cv := que.cv
	cl := que.close
	que.closeOnce.Do(func() {
		const waitBeforeBroadcast = 10 * time.Millisecond
		doClose = true
		close(cl)
		for {
			select {
			case <-stopped:
				return
			case <-time.After(waitBeforeBroadcast):
				cv.Broadcast()
			}
		}
	})
	if doClose {
		cv.L.Lock()
		que.data = nil
		cv.L.Unlock()
	}
	return nil
}

func (que *FIFO) run() {
	defer func() {
		close(que.ch)
		close(que.stopped)
	}()
	for {
		v, ok := que.fetch()
		if !ok {
			return
		}
		select {
		case <-que.close:
			return
		case que.ch <- v:
		}
	}
}

func (que *FIFO) fetch() (v any, ok bool) {
	que.cv.L.Lock()
	defer que.cv.L.Unlock()
	if que.data == nil {
		return v, ok
	}
	hasData := que.data.Len() != 0
	if !hasData {
		que.cv.Wait()
		hasData = que.data != nil && que.data.Len() != 0
	}
	if hasData {
		o := que.data.Front()
		v, ok = o.Value, true
		que.data.Remove(o)
	}
	return v, ok
}
