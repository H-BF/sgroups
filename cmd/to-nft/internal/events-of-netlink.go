package internal

import (
	"context"

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
	AgentSubj observer.Subject
	nl.NetlinkWatcher
}

// Run -
func (w *NetlinkEventSource) Run(ctx context.Context) error {
	log := logger.FromContext(ctx).Named("net-conf")
	log.Info("start")
	defer log.Info("stop")
	for stream := w.Stream(); ; {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case msgs, ok := <-stream:
			if !ok {
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
					log.Error(t)
					w.AgentSubj.Notify(NetlinkError{ErrMsg: t})
					return t
				}
			}
			if len(ev.Updates) > 0 {
				w.AgentSubj.Notify(ev)
			}
		}
	}
}
