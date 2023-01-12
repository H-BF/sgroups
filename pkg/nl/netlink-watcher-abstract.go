//go:build linux
// +build linux

package nl

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"

	"github.com/H-BF/corlib/pkg/jsonview"
	"github.com/H-BF/sgroups/internal/3d-party/vishvananda/netlink"
)

type (
	//Link is type alias
	Link = netlink.Link

	//WatcherMsg abstract message def
	WatcherMsg interface {
		isNetlinkWatcherMsg()
	}

	//LinkUpdateMsg network link update message
	LinkUpdateMsg struct {
		WID     WatcherID
		Link    Link
		Deleted bool
	}

	//AddrUpdateMsg address update message
	AddrUpdateMsg struct {
		WID       WatcherID
		Address   net.IPNet
		LinkIndex int
		Deleted   bool
	}

	//ErrMsg ...
	ErrMsg struct {
		WID WatcherID
		Err error
	}

	//NetlinkWatcher netlink watch streamer
	NetlinkWatcher interface {
		Stream() <-chan []WatcherMsg
		Close() error
	}

	//WatcherID is a watcher ID
	WatcherID = string
)

var (
	//ErrUnexpectedlyStopped on recieving bad message from 'netlink'
	ErrUnexpectedlyStopped = errors.New("watcher stream stopped unexpectedly")

	//ErrUnsupportedOption used unsupported option
	ErrUnsupportedOption = errors.New("unsupported option")
)

func (AddrUpdateMsg) isNetlinkWatcherMsg() {}

func (LinkUpdateMsg) isNetlinkWatcherMsg() {}

func (ErrMsg) isNetlinkWatcherMsg() {}

// MarshalJSON impl 'json.Marshaler'
func (e ErrMsg) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		ID string         `json:"wid,omitempty"`
		E  json.Marshaler `json:"error"`
	}{
		ID: e.WID,
		E:  jsonview.Marshaler(e.Err),
	})
}

// String impl 'stringer'
func (e ErrMsg) String() string {
	return e.Error()
}

// Error impl 'error'
func (e ErrMsg) Error() string {
	b, er := e.MarshalJSON()
	if er != nil {
		return "<?>"
	}
	return string(b)
}

// String impl 'stringer'
func (m AddrUpdateMsg) String() string {
	b, e := m.MarshalJSON()
	if e != nil {
		return "<?>"
	}
	return string(b)
}

// MarshalJSON impl 'json.Marshaler'
func (m AddrUpdateMsg) MarshalJSON() ([]byte, error) {
	ones, _ := m.Address.Mask.Size()
	obj := struct {
		Wather    WatcherID      `json:"wid,omitempty"`
		Address   json.Marshaler `json:"ip"`
		Subnet    string         `json:"subnet"`
		LinkIndex int            `json:"link_index"`
		Deleted   bool           `json:"deleted"`
	}{
		Wather:    m.WID,
		Address:   jsonview.Marshaler(m.Address.IP),
		LinkIndex: m.LinkIndex,
		Subnet:    fmt.Sprintf("/%v", ones),
		Deleted:   m.Deleted,
	}
	return json.Marshal(obj)
}

// String impl 'stringer'
func (m LinkUpdateMsg) String() string {
	b, e := m.MarshalJSON()
	if e != nil {
		return "<?>"
	}
	return string(b)
}

// MarshalJSON impl 'json.Marshaler'
func (m LinkUpdateMsg) MarshalJSON() ([]byte, error) {
	attrs := m.Link.Attrs()
	obj := struct {
		ID      string         `json:"wid,omitempty"`
		Type    string         `json:"type"`
		Name    string         `json:"name"`
		Index   int            `json:"index"`
		Ns      json.Marshaler `json:"ns,omitempty"`
		Deleted bool           `json:"deleted"`
	}{
		ID:      m.WID,
		Type:    m.Link.Type(),
		Name:    attrs.Name,
		Index:   attrs.Index,
		Ns:      jsonview.Marshaler(attrs.Namespace),
		Deleted: m.Deleted,
	}
	return json.Marshal(obj)
}
