package host

import (
	"bytes"
	"crypto/md5" //nolint:gosec
	"net"
	"sort"

	"github.com/H-BF/sgroups/internal/dict"
	"github.com/H-BF/sgroups/pkg/nl"

	"github.com/H-BF/corlib/pkg/slice"
	"github.com/c-robinson/iplib"
)

type (
	//UpdStrategy update strategy
	UpdStrategy uint

	//LinkID link ID dev
	LinkID = int

	//LinkRefs link refs
	LinkRefs struct {
		dict.HDict[LinkID, struct{}]
	}

	//IpAddr ip address
	IpAddr struct { //nolint:revive
		net.IPNet
		Links LinkRefs
	}

	//IPAdressesMapKey md5 from IpAddr.IPNet
	IPAdressesMapKey [md5.Size]byte

	//IPAdresses ip addresses
	IPAdresses struct {
		dict.HDict[IPAdressesMapKey, *IpAddr]
	}

	//IpDev ip device
	IpDev struct { //nolint:revive
		Name string
		ID   LinkID
	}

	//IpDevs ip devices
	IpDevs struct {
		dict.HDict[LinkID, IpDev] //nolint:revive
	}

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
	switch howUpd {
	case Update:
		r.Put(ref, struct{}{})
	case Delete:
		r.Del(ref)
	default:
		panic("UB")
	}
}

// Clone makes a copy
func (r LinkRefs) Clone() LinkRefs {
	var ret LinkRefs
	r.Iterate(ret.Insert)
	return ret
}

// Eq -
func (r LinkRefs) Eq(other LinkRefs) bool {
	return r.HDict.Eq(other.HDict, func(_, _ struct{}) bool {
		return true
	})
}

// Eq -
func (a IpAddr) Eq(b IpAddr) bool {
	return a.IP.Equal(b.IP) &&
		bytes.Equal(a.Mask, b.Mask) &&
		a.Links.Eq(b.Links)
}

// Key make map key
func (a IpAddr) Key() IPAdressesMapKey {
	s := append(
		append([]byte{}, a.IP.To16()...),
		a.Mask...,
	)
	return md5.Sum(s) //nolint:gosec
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
	x := IpAddr{IPNet: addr}
	k := x.Key()
	o := a.At(k)
	switch how {
	case Update:
		if o == nil {
			o = &x
		}
		o.Links.Upd(lnk, Update)
		a.Put(k, o)
	case Delete:
		if o != nil {
			o.Links.Upd(lnk, Delete)
			if o.Links.Len() == 0 {
				a.Del(k)
			}
		}
	default:
		panic("UB")
	}
}

// Clone makes a copy
func (a IPAdresses) Clone() IPAdresses {
	var ret IPAdresses
	a.Iterate(ret.Insert)
	return ret
}

// Eq -
func (a IPAdresses) Eq(b IPAdresses) bool {
	return a.HDict.Eq(b.HDict, func(vL, vR *IpAddr) bool {
		return vL.Eq(*vR)
	})
}

// Upd update devs
func (devs *IpDevs) Upd(d IpDev, how UpdStrategy) {
	switch how {
	case Update:
		devs.Put(d.ID, d)
	case Delete:
		devs.Del(d.ID)
	default:
		panic("UB")
	}
}

// Clone makes a copy
func (devs IpDevs) Clone() IpDevs {
	var ret IpDevs
	devs.Iterate(ret.Insert)
	return ret
}

// Eq -
func (devs IpDevs) Eq(other IpDevs) bool {
	return devs.HDict.Eq(other.HDict, func(vL, vR IpDev) bool {
		return vL == vR
	})
}

// Eq -
func (conf NetConf) Eq(other NetConf) bool {
	return conf.IpDevs.Eq(other.IpDevs) &&
		conf.IPAdresses.Eq(other.IPAdresses)
}

// Clone -
func (conf NetConf) Clone() NetConf {
	return NetConf{
		IPAdresses: conf.IPAdresses.Clone(),
		IpDevs:     conf.IpDevs.Clone(),
	}
}

// LocalIPs get effective local unique IP lists
func (conf NetConf) LocalIPs() (IPv4 []net.IP, IPv6 []net.IP) {
	conf.IPAdresses.Iterate(func(_ IPAdressesMapKey, a *IpAddr) bool {
		a.Links.Iterate(func(lid LinkID, _ struct{}) bool {
			if _, ok := conf.IpDevs.Get(lid); ok {
				switch len(a.IP) {
				case net.IPv4len:
					IPv4 = append(IPv4, a.IP)
				case net.IPv6len:
					IPv6 = append(IPv6, a.IP)
				}
			}
			return true
		})
		return true
	})
	type iplist = []net.IP
	for _, ips := range []*iplist{&IPv4, &IPv6} {
		sort.Sort(iplib.ByIP(*ips))
		_ = slice.DedupSlice(ips, func(i, j int) bool {
			return iplib.CompareIPs((*ips)[i], (*ips)[j]) == 0
		})
	}
	return IPv4, IPv6
}

// UpdFromWatcher updates conf with messages came from netlink-watcher
func (conf *NetConf) UpdFromWatcher(msgs ...nl.WatcherMsg) {
	for _, m := range msgs {
		switch v := m.(type) {
		case nl.AddrUpdateMsg:
			conf.IPAdresses.Upd(
				v.LinkIndex,
				v.Address,
				tern(v.Deleted, Delete, Update))
		case nl.LinkUpdateMsg:
			attrs := v.Link.Attrs()
			conf.IpDevs.Upd(
				IpDev{
					ID:   attrs.Index,
					Name: attrs.Name,
				},
				tern(v.Deleted, Delete, Update),
			)
		}
	}
}

func tern[tval any](cond bool, v1, v2 tval) tval {
	if cond {
		return v1
	}
	return v2
}
