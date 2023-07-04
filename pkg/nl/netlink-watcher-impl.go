//go:build linux
// +build linux

package nl

import (
	"fmt"
	"reflect"
	"runtime"
	"sync"
	"time"

	"github.com/H-BF/sgroups/internal/3d-party/vishvananda/netlink"
	"github.com/pkg/errors"
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
		case WithAgeOfMaturity:
			age = t.Age
		case WithNetns:
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
		id:            id,
		chClose:       make(chan struct{}),
		chErrors:      make(chan error),
		ageOfMaturity: age,
	}
	var err error
	defer func() {
		if err != nil {
			close(ret.chClose)
			close(ret.chErrors)
			if ret.netns != nil {
				_ = ret.netns.Close()
			}
		}
	}()

	if len(ns) > 0 {
		var nsh netns.NsHandle
		if nsh, err = netns.GetFromName(ns); err != nil {
			return nil, errors.WithMessagef(err, "accessing netns '%s'", ns)
		}
		ret.netns = &nsh
	}

	ret.sel = []reflect.SelectCase{{
		Dir:  reflect.SelectRecv,
		Chan: reflect.ValueOf(ret.chClose),
	}, {
		Dir:  reflect.SelectRecv,
		Chan: reflect.ValueOf(ret.chErrors),
	}}
	if sco&IgnoreLinks == 0 {
		o := netlink.LinkSubscribeOptions{
			ListExisting:  true,
			ErrorCallback: ret.onGotError,
			Namespace:     ret.netns,
		}
		ch := make(chan netlink.LinkUpdate)
		if err = netlink.LinkSubscribeWithOptions(ch, ret.chClose, o); err != nil {
			close(ch)
			return nil, err
		}
		ret.sel = append(ret.sel, reflect.SelectCase{
			Dir:  reflect.SelectRecv,
			Chan: reflect.ValueOf(ch),
		})
	}
	if sco&IgnoreAddress == 0 {
		o := netlink.AddrSubscribeOptions{
			ListExisting:  true,
			ErrorCallback: ret.onGotError,
			Namespace:     ret.netns,
		}
		ch := make(chan netlink.AddrUpdate)
		if err = netlink.AddrSubscribeWithOptions(ch, ret.chClose, o); err != nil {
			close(ch)
			return nil, err
		}
		ret.sel = append(ret.sel, reflect.SelectCase{
			Dir:  reflect.SelectRecv,
			Chan: reflect.ValueOf(ch),
		})
	}
	return ret, nil
}

type (
	netlinkWatcherImpl struct {
		id            WatcherID
		chErrors      chan error
		chClose       chan struct{}
		stream        chan []WatcherMsg
		ageOfMaturity time.Duration
		onceRun       sync.Once
		onceClose     sync.Once
		sel           []reflect.SelectCase
		netns         *netns.NsHandle
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

	//WithAgeOfMaturity - every packet accumulates updates during some duration then
	//it sends to consumer
	WithAgeOfMaturity struct {
		WatcherOption
		Age time.Duration
	}

	// WithNetns select net NS(by name) for watching
	WithNetns struct {
		WatcherOption
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
	w.onceRun.Do(func() {
		w.stream = make(chan []WatcherMsg)
		go func() {
			age := w.ageOfMaturity
			if age < time.Second {
				age = time.Second
			}
			var packet []WatcherMsg
			var t *time.Timer
			accumulate := func(m WatcherMsg) {
				if t == nil {
					t = time.NewTimer(age)
				}
				packet = append(packet, m)
			}
			send := func(msgs []WatcherMsg) {
				if len(msgs) > 0 {
					select {
					case <-w.chClose:
					case w.stream <- msgs:
					}
				}
			}
			defer func() {
				if t != nil {
					_ = t.Stop()
				}
				close(w.stream)
			}()
			for {
				sel := w.sel
				if t != nil {
					sel = append(sel, reflect.SelectCase{
						Chan: reflect.ValueOf(t.C),
						Dir:  reflect.SelectRecv,
					})
				}
				chosen, recv, ok := reflect.Select(sel)
				if chosen == 0 { //we are closed then do exit
					break
				}
				if !ok { //it is stopped unexpectedly
					send([]WatcherMsg{ErrMsg{
						WID: w.id,
						Err: ErrUnexpectedlyStopped,
					}})
					break
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
					send(packet)
					t, packet = nil, nil
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
		runtime.SetFinalizer(w, func(o *netlinkWatcherImpl) {
			close(o.chErrors)
		})
		close(w.chClose)
		if w.netns != nil {
			_ = w.netns.Close()
		}
	})
	return nil
}

func (w *netlinkWatcherImpl) onGotError(e error) {
	select {
	case <-w.chClose:
	case w.chErrors <- e:
	}
}

func (scopeOfUpdates) isWatcherOption() {}
