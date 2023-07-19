package sgroups

import (
	"net"
	"reflect"

	model "github.com/H-BF/sgroups/internal/models/sgroups"

	"github.com/pkg/errors"
)

type (
	//Scope scope interface
	Scope interface {
		privateScope()
	}

	scopedNot struct {
		Scope
	}

	scopedAnd struct {
		L, R Scope
	}

	scopedOr struct {
		L, R Scope
	}

	noScope struct{}

	scopedIPs struct {
		All bool
		IPs []net.IP
	}

	scopedNetworks struct {
		Names map[model.NetworkName]struct{}
	}

	//ScopedNetTransport network transport scope
	ScopedNetTransport model.NetworkTransport

	scopedSGRuleIdentity map[string]bool

	scopedSG     map[string]struct{}
	scopedSGFrom map[string]struct{}
	scopedSGTo   map[string]struct{}

	//KindOfScope all kind of scope
	KindOfScope interface {
		Scope
		scopedIPs | scopedNetworks | ScopedNetTransport | scopedSGRuleIdentity |
			scopedSGFrom | scopedSGTo | scopedSG |
			scopedAnd | scopedOr | scopedNot | noScope
	}
)

// ErrUnexpectedScope -
var ErrUnexpectedScope = errors.New("unexpected scope")

// NoScope no any scope
var NoScope noScope

// And logical and cope
func And(t1 Scope, t2 Scope) Scope {
	return scopedAnd{L: t1, R: t2}
}

// Or logical or scope
func Or(t1 Scope, t2 Scope) Scope {
	return scopedOr{L: t1, R: t2}
}

// Not negate scope
func Not(t Scope) Scope {
	return scopedNot{Scope: t}
}

// SGFrom makes sec-group-'From' name scope used in Sg rules
func SGFrom(one string, other ...string) Scope {
	ret := scopedSGFrom{
		one: {},
	}
	for i := range other {
		ret[other[i]] = struct{}{}
	}
	return ret
}

// SGTo makes sec-group-'To' name scope used in Sg rules
func SGTo(one string, other ...string) Scope {
	ret := scopedSGTo{
		one: {},
	}
	for i := range other {
		ret[other[i]] = struct{}{}
	}
	return ret
}

// SG maks security group name(s) scope
func SG(one string, other ...string) Scope {
	ret := scopedSG{
		one: {},
	}
	for i := range other {
		ret[other[i]] = struct{}{}
	}
	return ret
}

// IPs makes IP(s) scope
func IPs(one net.IP, all bool, other ...net.IP) Scope {
	return scopedIPs{
		All: all,
		IPs: append([]net.IP{one}, other...),
	}
}

// NetworkNames makes networks name(s) scope
func NetworkNames(one model.NetworkName, other ...model.NetworkName) Scope {
	ret := scopedNetworks{
		Names: map[model.NetworkName]struct{}{
			one: {},
		},
	}
	for i := range other {
		ret.Names[other[i]] = struct{}{}
	}
	return ret
}

// SGRule makes SG rule scope
func SGRule(others ...model.SGRule) Scope {
	ret := scopedSGRuleIdentity{}
	for i := range others {
		h := others[i].IdentityHash()
		ret[h] = true
	}
	return ret
}

func (scopedNot) privateScope()            {}
func (scopedOr) privateScope()             {}
func (scopedAnd) privateScope()            {}
func (noScope) privateScope()              {}
func (scopedIPs) privateScope()            {}
func (scopedNetworks) privateScope()       {}
func (scopedSG) privateScope()             {}
func (scopedSGFrom) privateScope()         {}
func (scopedSGTo) privateScope()           {}
func (ScopedNetTransport) privateScope()   {}
func (scopedSGRuleIdentity) privateScope() {}

type filterKindArg interface {
	model.Network | model.SecurityGroup | model.SGRule
}

type filterTree[filterArgT filterKindArg] struct {
	filter func(filterArgT) bool
	next   func(bool, filterArgT) bool
}

func (ft filterTree[filterArgT]) invoke(arg filterArgT) bool {
	ret := ft.filter(arg)
	if ft.next != nil {
		ret = ft.next(ret, arg)
	}
	return ret
}

func (ft *filterTree[filterArgT]) init(sc Scope) bool { //nolint:gocyclo
	var ret bool
	var x filterTree[filterArgT]
	switch t := sc.(type) {
	case scopedAnd:
		if ret = x.init(t.L); ret {
			var ft1 filterTree[filterArgT]
			if ret = ft1.init(t.R); ret {
				x.next = func(r bool, a filterArgT) bool {
					if r {
						r = ft1.invoke(a)
					}
					return r
				}
			}
		}
	case scopedOr:
		if ret = x.init(t.L); ret {
			var ft1 filterTree[filterArgT]
			if ret = ft1.init(t.R); ret {
				x.next = func(r bool, a filterArgT) bool {
					if !r {
						r = ft1.invoke(a)
					}
					return r
				}
			}
		}
	case scopedNot:
		var f1 filterTree[filterArgT]
		if ret = f1.init(t.Scope); ret {
			x.filter = func(a filterArgT) bool {
				return !f1.invoke(a)
			}
		}
	case noScope:
		ret = true
		x.filter = func(_ filterArgT) bool {
			return true
		}
	default:
		meta, _ := t.(interface {
			meta() metaInfo
		})
		if meta != nil {
			var a *filterArgT
			if meth, ok := meta.meta()[reflect.TypeOf(a).Elem()]; ok {
				dest := reflect.ValueOf(&x.filter).Elem()
				if meth.Type().AssignableTo(dest.Type()) {
					dest.Set(meth)
					ret = true
				}
			}
		}
	}
	if ret {
		*ft = x
	}
	return ret
}

type metaInfo = map[reflect.Type]reflect.Value

func (p scopedIPs) meta() metaInfo {
	return metaInfo{
		reflect.TypeOf((*model.Network)(nil)).Elem(): reflect.ValueOf(p.inNetwork),
	}
}

func (p *scopedIPs) inNetwork(network model.Network) bool {
	n := 0
	for _, ip := range p.IPs {
		if !network.Net.Contains(ip) {
			if p.All {
				return false
			}
			continue
		}
		if !p.All {
			return true
		}
		n++
	}
	return n == len(p.IPs) && n > 0
}

func (p *scopedNetworks) inNetwork(network model.Network) bool {
	_, ok := p.Names[network.Name]
	return ok
}

func (p *scopedNetworks) inSG(sg model.SecurityGroup) bool {
	for i := range sg.Networks {
		if _, ok := p.Names[sg.Networks[i]]; ok {
			return true
		}
	}
	return false
}

func (p *scopedNetworks) inSGRule(rule model.SGRule) bool {
	return p.inSG(rule.SgFrom) ||
		p.inSG(rule.SgTo)
}

func (p scopedNetworks) meta() metaInfo {
	return metaInfo{
		reflect.TypeOf((*model.SecurityGroup)(nil)).Elem(): reflect.ValueOf(p.inSG),

		reflect.TypeOf((*model.Network)(nil)).Elem(): reflect.ValueOf(p.inNetwork),

		reflect.TypeOf((*model.SGRule)(nil)).Elem(): reflect.ValueOf(p.inSGRule),
	}
}

func (p scopedSG) inSG(rule model.SecurityGroup) bool {
	_, ok := p[rule.Name]
	return ok
}

func (p scopedSG) meta() metaInfo {
	return metaInfo{
		reflect.TypeOf((*model.SecurityGroup)(nil)).Elem(): reflect.ValueOf(p.inSG),
	}
}

func (p scopedSGFrom) inSGRule(rule model.SGRule) bool {
	_, ok := p[rule.SgFrom.Name]
	return ok
}

func (p scopedSGFrom) meta() metaInfo {
	return metaInfo{
		reflect.TypeOf((*model.SGRule)(nil)).Elem(): reflect.ValueOf(p.inSGRule),
	}
}

func (p scopedSGTo) inSGRule(rule model.SGRule) bool {
	_, ok := p[rule.SgTo.Name]
	return ok
}

func (p scopedSGTo) meta() metaInfo {
	return metaInfo{
		reflect.TypeOf((*model.SGRule)(nil)).Elem(): reflect.ValueOf(p.inSGRule),
	}
}

func (p ScopedNetTransport) inSGRule(rule model.SGRule) bool {
	return rule.Transport == model.NetworkTransport(p)
}

func (p ScopedNetTransport) meta() metaInfo {
	return metaInfo{
		reflect.TypeOf((*model.SGRule)(nil)).Elem(): reflect.ValueOf(p.inSGRule),
	}
}

func (p scopedSGRuleIdentity) inSGRule(rule model.SGRule) bool {
	h := rule.IdentityHash()
	return p[h]
}

func (p scopedSGRuleIdentity) meta() metaInfo {
	return metaInfo{
		reflect.TypeOf((*model.SGRule)(nil)).Elem(): reflect.ValueOf(p.inSGRule),
	}
}
