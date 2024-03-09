package nl

import (
	"context"
	"sync"

	"github.com/H-BF/sgroups/internal/3d-party/vishvananda/netlink"

	"github.com/pkg/errors"
	"github.com/vishvananda/netns"
)

// NewLinkLister -
func NewLinkLister(ctx context.Context, opts ...linkListerOpt) (LinkLister, error) {
	const api = "NewLinkLister"
	var netNsName string
	for _, o := range opts {
		switch t := o.(type) {
		case WithNetnsName:
			netNsName = t.Netns
		}
	}
	var ret linkListerImpl
	if len(netNsName) != 0 {
		var h netns.NsHandle
		h, e := netns.GetFromName(netNsName)
		if e != nil {
			return nil, errors.WithMessagef(e, "%s: on open netns '%s'", api, netNsName)
		}
		ret.ns = &h
	}
	var err error
	if ret.ns == nil {
		ret.h, err = netlink.NewHandle()
	} else {
		ret.h, err = netlink.NewHandleAt(*ret.ns)
	}
	if err != nil {
		if ret.ns != nil {
			_ = ret.ns.Close()
		}
		return nil, errors.WithMessage(err, api)
	}
	return &ret, nil
}

// LinkLister -
type LinkLister interface {
	List(context.Context) ([]Link, error)
	Addrs(context.Context, Link) ([]Addr, error)
	Close() error
}

type linkListerOpt interface {
	isLinkListerOpt()
}

type linkListerImpl struct {
	ns        *netns.NsHandle
	h         *netlink.Handle
	closeOnce sync.Once
}

// List -
func (api *linkListerImpl) List(_ context.Context) ([]Link, error) {
	return api.h.LinkList()
}

// Addrs -
func (api *linkListerImpl) Addrs(_ context.Context, lnk Link) ([]Addr, error) {
	return api.h.AddrList(lnk, netlink.FAMILY_ALL)
}

// Close -
func (api *linkListerImpl) Close() error {
	api.closeOnce.Do(func() {
		if api.h != nil {
			api.h.Delete()
		}
		if api.ns != nil {
			_ = api.ns.Close()
		}
	})
	return nil
}
