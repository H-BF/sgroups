package internal

import (
	"context"
	"fmt"
	"sync"

	"github.com/H-BF/sgroups/pkg/nl"

	"github.com/H-BF/corlib/logger"
	"github.com/H-BF/corlib/pkg/patterns/observer"
)

type ( // events from netlink
	// NetlinkUpdates -
	NetlinkUpdates struct {
		Updates []nl.WatcherMsg

		observer.EventType
	}

	// NetlinkError -
	NetlinkError struct {
		nl.ErrMsg

		observer.EventType
	}
)

// NetlinkEventSource -
type NetlinkEventSource struct {
	Subject observer.Subject
	nl.NetlinkWatcher

	runOnce   sync.Once
	closeOnce sync.Once
	stopped   chan struct{}
}

// Close -
func (w *NetlinkEventSource) Close() error {
	w.closeOnce.Do(func() {
		w.runOnce.Do(func() {})
		w.NetlinkWatcher.Close()
		if w.stopped != nil {
			<-w.stopped
		}
	})
	return nil
}

// Run -
func (w *NetlinkEventSource) Run(ctx context.Context) error {
	const job = "net-conf-watcher"

	var neverRun bool
	w.runOnce.Do(func() {
		neverRun = true
	})
	log := logger.FromContext(ctx).Named(job)
	if !neverRun {
		return fmt.Errorf("%s: it has been run or closed yet", job)
	}
	w.stopped = make(chan struct{})
	log.Info("start")
	defer func() {
		log.Info("stop")
		close(w.stopped)
	}()
	stream := w.Stream()
	if stream == nil {
		log.Info("will exit cause it has closed")
		return nil
	}
	for {
		select {
		case <-ctx.Done():
			log.Info("will exit cause it has canceled")
			return ctx.Err()
		case msgs, ok := <-stream:
			if !ok {
				log.Info("will exit cause it has closed")
				return nil
			}
			var ev NetlinkUpdates
			for _, m := range msgs {
				switch t := m.(type) {
				case nl.AddrUpdateMsg:
					ev.Updates = append(ev.Updates, t)
				case nl.LinkUpdateMsg:
					ev.Updates = append(ev.Updates, t)
				case nl.ErrMsg:
					log.Errorf("will exit cause %v", t)
					w.Subject.Notify(NetlinkError{ErrMsg: t})
					return t
				}
			}
			if len(ev.Updates) > 0 {
				w.Subject.Notify(ev)
			}
		}
	}
}
