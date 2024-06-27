package agent

import (
	"context"
	"fmt"
	"sync"

	"github.com/H-BF/corlib/logger"
	"github.com/H-BF/corlib/pkg/nl"
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
	NetNS string

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
		w.stopped = make(chan struct{})
	})
	if !neverRun {
		return fmt.Errorf("%s: it has been run or closed yet", job)
	}
	log := logger.FromContext(ctx).Named(job)
	log.Info("start")
	defer func() {
		log.Info("stop")
		close(w.stopped)
	}()
	if err := w.gatherLinkState(ctx); err != nil {
		log.Errorf("will exit cause %v", err)
		return err
	}
	for stream := w.Stream(); ; {
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

func (w *NetlinkEventSource) gatherLinkState(ctx context.Context) (err error) {
	defer func() {
		if err != nil {
			w.Subject.Notify(NetlinkError{ErrMsg: nl.ErrMsg{Err: err}})
		}
	}()

	var lister nl.LinkLister
	if lister, err = nl.NewLinkLister(ctx, nl.WithNetnsName(w.NetNS)); err != nil {
		return err
	}
	defer lister.Close() //nolint
	var links []nl.Link
	if links, err = lister.List(ctx); err != nil {
		return err
	}
	var ret NetlinkUpdates
	for _, lnk := range links {
		var addrs []nl.Addr
		if addrs, err = lister.Addrs(ctx, lnk); err != nil {
			return err
		}
		for _, a := range addrs {
			ret.Updates = append(ret.Updates,
				nl.AddrUpdateMsg{
					Address:   *a.IPNet,
					LinkIndex: lnk.Attrs().Index,
				})
		}
	}
	if len(ret.Updates) > 0 {
		w.Subject.Notify(ret)
	}
	return nil
}
