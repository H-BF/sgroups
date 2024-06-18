//go:build linux
// +build linux

package nl

import (
	"fmt"
	"reflect"
	"sync"
	"time"

	"github.com/pkg/errors"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"go.uber.org/multierr"
	"golang.org/x/sys/unix"
)

// NewNetlinkWatcher creates NetlinkWatcher instance
func NewNetlinkWatcher(opts ...WatcherOption) (NetlinkWatcher, error) {
	var id WatcherID
	var age time.Duration
	var ns string
	sco := scopeNone

	for _, o := range opts {
		switch t := o.(type) {
		case WithID:
			id = t.WatcherID
		case scopeOfUpdates:
			sco |= t
		case WithLinger:
			age = t.Linger
		case WithNetnsName:
			ns = t.Netns
		default:
			return nil, multierr.Append(ErrUnsupportedOption,
				errors.Errorf("bad option '%T'", t))
		}
	}
	if test := IgnoreAddress | IgnoreLinks; sco&test == test {
		return nil, errors.New("nothing to watch")
	}
	ret := &netlinkWatcherImpl{
		id:             id,
		lingerDuration: age,
		sco:            sco,
		chClose:        make(chan struct{}),
		chErrors:       make(chan error, 100), //nolint:mnd
		stream:         make(chan []WatcherMsg),
	}
	if len(ns) > 0 {
		nsh, err := netns.GetFromName(ns)
		if err != nil {
			close(ret.chClose)
			close(ret.chErrors)
			close(ret.stream)
			return nil, errors.WithMessagef(err, "accessing netns '%s'", ns)
		}
		ret.netns = &nsh
	}
	return ret, nil
}

type (
	netlinkWatcherImpl struct {
		id             WatcherID
		sco            scopeOfUpdates
		chErrors       chan error
		chClose        chan struct{}
		stopped        chan struct{}
		stream         chan []WatcherMsg
		lingerDuration time.Duration
		onceRun        sync.Once
		onceClose      sync.Once
		netns          *netns.NsHandle
		linger         *time.Timer
	}

	// WatcherOption ...
	WatcherOption interface {
		isWatcherOption()
	}

	//WithID sets ID to watcher
	WithID struct {
		WatcherOption
		WatcherID
	}

	//WithLinger - every packet accumulates updates during some duration then
	//it sends to consumer
	WithLinger struct {
		WatcherOption
		Linger time.Duration
	}

	// WithNetnsName select net NS(by name) for watching
	WithNetnsName struct {
		WatcherOption
		linkListerOpt
		Netns string
	}

	scopeOfUpdates uint32
)

const (
	scopeNone scopeOfUpdates = (1 << iota) >> 1

	//IgnoreLinks does not send 'Links'
	IgnoreLinks

	//IgnoreAddress does not send 'Adresses'
	IgnoreAddress
)

var _ NetlinkWatcher = (*netlinkWatcherImpl)(nil)

// Stream impl 'NetlinkWatcher'
func (w *netlinkWatcherImpl) Stream() <-chan []WatcherMsg {
	const minLingerDuration = 333 * time.Millisecond

	w.onceRun.Do(func() {
		var packet []WatcherMsg
		accumulate := func(m WatcherMsg) {
			if w.lingerDuration < minLingerDuration {
				w.send(m)
			} else {
				if w.linger == nil {
					w.linger = time.NewTimer(w.lingerDuration)
				}
				packet = append(packet, m)
			}
		}
		w.stopped = make(chan struct{})
		go func() {
			defer close(w.stopped)
			sel0, err := w.prepare(w.sco)
			if err != nil {
				w.send(ErrMsg{
					WID: w.id,
					Err: err,
				})
				return
			}
			for {
				sel := sel0
				if w.linger != nil {
					sel = append(sel, reflect.SelectCase{
						Chan: reflect.ValueOf(w.linger.C),
						Dir:  reflect.SelectRecv,
					})
				}
				chosen, recv, ok := reflect.Select(sel)
				if chosen == 0 { //we are closed then do exit
					return
				}
				if !ok { //it is stopped unexpectedly
					w.send(ErrMsg{
						WID: w.id,
						Err: ErrUnexpectedlyStopped,
					})
					return
				}
				switch v := recv.Interface().(type) {
				case netlink.AddrUpdate:
					accumulate(AddrUpdateMsg{
						WID:       w.id,
						LinkIndex: v.LinkIndex,
						Address:   v.LinkAddress,
						Deleted:   !v.NewAddr,
					})
				case netlink.LinkUpdate:
					accumulate(LinkUpdateMsg{
						WID:     w.id,
						Link:    v.Link,
						Deleted: v.Header.Type == unix.RTM_DELLINK,
					})
				case error:
					accumulate(ErrMsg{
						WID: w.id,
						Err: v,
					})
				case time.Time:
					w.send(packet...)
					w.linger, packet = nil, packet[:0]
				default:
					panic(fmt.Sprintf("got unexpected type '%T'", v))
				}
			}
		}()
	})
	return w.stream
}

// Close impl 'NetlinkWatcher'
func (w *netlinkWatcherImpl) Close() error {
	w.onceClose.Do(func() {
		close(w.chClose)
		w.onceRun.Do(func() {})
		if w.stopped != nil {
			<-w.stopped
		}
		if w.linger != nil {
			_ = w.linger.Stop()
		}
		if w.netns != nil {
			_ = w.netns.Close()
		}
		close(w.stream)
	})
	return nil
}

func (w *netlinkWatcherImpl) onGotError(e error) {
	select {
	case <-w.chClose:
	case w.chErrors <- e:
	}
}

func (w *netlinkWatcherImpl) prepare(sco scopeOfUpdates) (sel []reflect.SelectCase, err error) {
	const recvCap = 1000
	sel = append(sel,
		reflect.SelectCase{
			Dir:  reflect.SelectRecv,
			Chan: reflect.ValueOf(w.chClose),
		},
		reflect.SelectCase{
			Dir:  reflect.SelectRecv,
			Chan: reflect.ValueOf(w.chErrors),
		},
	)
	if sco&IgnoreLinks == 0 {
		o := netlink.LinkSubscribeOptions{
			ListExisting:  true,
			ErrorCallback: w.onGotError,
			Namespace:     w.netns,
		}
		recvCh := make(chan netlink.LinkUpdate, recvCap)
		if err = netlink.LinkSubscribeWithOptions(recvCh, w.chClose, o); err != nil {
			close(recvCh)
			return nil, err
		}
		sel = append(sel, reflect.SelectCase{
			Dir:  reflect.SelectRecv,
			Chan: reflect.ValueOf(recvCh),
		})
	}
	if sco&IgnoreAddress == 0 {
		o := netlink.AddrSubscribeOptions{
			ListExisting:  true,
			ErrorCallback: w.onGotError,
			Namespace:     w.netns,
			//ReceiveBufferSize: 65536,
		}
		recvCh := make(chan netlink.AddrUpdate, recvCap)
		if err = netlink.AddrSubscribeWithOptions(recvCh, w.chClose, o); err != nil {
			close(recvCh)
			return nil, err
		}
		sel = append(sel, reflect.SelectCase{
			Dir:  reflect.SelectRecv,
			Chan: reflect.ValueOf(recvCh),
		})
	}
	return sel, err
}

func (w *netlinkWatcherImpl) send(msgs ...WatcherMsg) {
	if len(msgs) > 0 {
		select {
		case <-w.chClose:
		case w.stream <- msgs:
		}
	}
}

func (scopeOfUpdates) isWatcherOption() {}
