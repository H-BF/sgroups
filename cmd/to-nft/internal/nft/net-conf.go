package nft

import (
	"crypto/md5"
	"net"
	"sort"

	"github.com/H-BF/corlib/pkg/slice"
	"github.com/H-BF/sgroups/pkg/nl"
	"github.com/c-robinson/iplib"
)

type (
	//UpdStrategy update strategy
	UpdStrategy = uint

	//LinkID link ID dev
	LinkID = int

	//LinkRefs link refs
	LinkRefs map[LinkID]struct{}

	//IpAddr ip address
	IpAddr struct {
		net.IPNet
		Links LinkRefs
	}

	//IPAdressesMapKey md5 from IpAddr.IPNet
	IPAdressesMapKey = [md5.Size]byte

	//IPAdresses ip addresses
	IPAdresses map[IPAdressesMapKey]*IpAddr

	//IpDev ip device
	IpDev struct {
		Name string
		ID   LinkID
	}

	//IpDevs ip devices
	IpDevs map[LinkID]IpDev

	//NetConf network conf
	NetConf struct {
		IpDevs
		IPAdresses
	}
)

const (
	//Update use insert/update
	Update UpdStrategy = iota

	//Delete use delete
	Delete
)

// Upd modifies references
func (r *LinkRefs) Upd(ref LinkID, howUpd UpdStrategy) {
	if (*r) == nil {
		*r = make(LinkRefs)
	}
	switch howUpd {
	case Update:
		(*r)[ref] = struct{}{}
	case Delete:
		delete((*r), ref)
	default:
		panic("UB")
	}
}

// Clone makes a copy
func (r LinkRefs) Clone() LinkRefs {
	ret := make(LinkRefs)
	if len(r) > 0 {
		for k, v := range r {
			ret[k] = v
		}
	}
	return ret
}

// Key make map key
func (a IpAddr) Key() IPAdressesMapKey {
	s := append(
		append([]byte{}, a.IP.To16()...),
		a.Mask...,
	)
	return md5.Sum(s)
}

// Clone makes a copy
func (a IpAddr) Clone() IpAddr {
	ret := IpAddr{
		Links: a.Links.Clone(),
	}
	ret.IP = iplib.CopyIP(ret.IP)
	ret.Mask = append(ret.Mask, a.Mask...)
	return ret
}

// Upd upfdate with IP
func (a *IPAdresses) Upd(lnk LinkID, addr net.IPNet, how UpdStrategy) {
	if (*a) == nil {
		*a = make(IPAdresses)
	}
	x := IpAddr{IPNet: addr}
	k := x.Key()
	o := (*a)[k]
	switch how {
	case Update:
		if o == nil {
			o = &x
		}
		o.Links.Upd(lnk, Update)
		(*a)[k] = o
	case Delete:
		if o != nil {
			o.Links.Upd(lnk, Delete)
			if len(o.Links) == 0 {
				delete(*a, k)
			}
		}
	default:
		panic("UB")
	}
}

// Clone makes a copy
func (a IPAdresses) Clone() IPAdresses {
	ret := make(IPAdresses)
	if len(a) > 0 {
		for _, p := range a {
			addr := p.Clone()
			ret[addr.Key()] = &addr
		}
	}
	return ret
}

// Upd update devs
func (devs *IpDevs) Upd(d IpDev, how UpdStrategy) {
	if (*devs) == nil {
		*devs = make(IpDevs)
	}
	switch how {
	case Update:
		(*devs)[d.ID] = d
	case Delete:
		delete(*devs, d.ID)
	default:
		panic("UB")
	}
}

// Clone makes a copy
func (devs IpDevs) Clone() IpDevs {
	ret := make(IpDevs)
	if len(devs) > 0 {
		for k, v := range devs {
			ret[k] = v
		}
	}
	return ret
}

// ActualIPs get actual unique IP list
func (conf NetConf) ActualIPs() []net.IP {
	var ret []net.IP
	for _, a := range conf.IPAdresses {
		for lid := range a.Links {
			if _, ok := conf.IpDevs[lid]; ok {
				ret = append(ret, a.IP)
				break
			}
		}
	}
	sort.Slice(ret, func(i, j int) bool {
		return iplib.CompareIPs(ret[i], ret[j]) < 0
	})
	_ = slice.DedupSlice(&ret, func(i, j int) bool {
		return iplib.CompareIPs(ret[i], ret[j]) == 0
	})
	return ret
}

// Init - inits internals
func (conf *NetConf) Init() {
	conf.IPAdresses = make(IPAdresses)
	conf.IpDevs = make(IpDevs)
}

// UpdFromWatcher updates conf with messages came from netlink-watcher
func (conf *NetConf) UpdFromWatcher(msgs ...nl.WatcherMsg) {
	for _, m := range msgs {
		switch v := m.(type) {
		case nl.AddrUpdateMsg:
			h := Update
			if v.Deleted {
				h = Delete
			}
			conf.IPAdresses.Upd(v.LinkIndex, v.Address, h)
		case nl.LinkUpdateMsg:
			h := Update
			if v.Deleted {
				h = Delete
			}
			attrs := v.Link.Attrs()
			conf.IpDevs.Upd(IpDev{
				ID:   attrs.Index,
				Name: attrs.Name,
			}, h)
		}
	}
}

/*//
// IsEq check equality
func (a IPAdresses) IsEq(other IPAdresses) bool {
	if n := len(a); n == len(other) {
		if n > 0 {
			for k := range a {
				if _, f := other[k]; !f {
					return false
				}
			}
		}
		return true
	}
	return false
}
*/
