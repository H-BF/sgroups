package sgroups

import (
	"net"
	"reflect"

	model "github.com/H-BF/sgroups/v2/internal/domains/sgroups"

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

	scopedSGRuleIdentity map[string]model.SGRuleIdentity

	scopedFqdnRuleIdentity map[string]model.FQDNRuleIdentity

	scopedSgIcmpIdentity map[string]model.SgIcmpRuleID

	scopedSgSgIcmpIdentity map[string]model.SgSgIcmpRuleID

	scopedCidrSgRuleIdentity map[string]model.IECidrSgRuleIdenity

	scopedCidrSgIcmpRuleIdentity map[string]model.IECidrSgIcmpRuleID

	scopedSgSgRuleIdentity map[string]model.IESgSgRuleIdentity

	scopedIESgSgIcmpRuleIdentity map[string]model.IESgSgIcmpRuleID

	scopedSG      map[string]struct{}
	scopedSGFrom  map[string]struct{}
	scopedSGTo    map[string]struct{}
	scopedSGLocal map[string]struct{}
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
func SG(names ...string) Scope {
	ret := make(scopedSG)
	for i := range names {
		ret[names[i]] = struct{}{}
	}
	return ret
}

// SGLocal makes local security group name(s) scope
func SGLocal(one string, other ...string) Scope {
	ret := scopedSGLocal{
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
func NetworkNames(names ...model.NetworkName) Scope {
	ret := scopedNetworks{
		Names: make(map[model.NetworkName]struct{}),
	}
	for i := range names {
		ret.Names[names[i]] = struct{}{}
	}
	return ret
}

// PKScopeOfSGRules makes SG rule scope
func PKScopeOfSGRules(others ...model.SGRule) Scope {
	ret := scopedSGRuleIdentity{}
	for _, o := range others {
		ret[o.ID.IdentityHash()] = o.ID
	}
	return ret
}

// PKScopeOfFQDNRules makes FQDN rule scope
func PKScopeOfFQDNRules(others ...model.FQDNRule) Scope {
	ret := scopedFqdnRuleIdentity{}
	for _, o := range others {
		ret[o.ID.IdentityHash()] = o.ID
	}
	return ret
}

// PKScopeOfSgIcmpRules makes SG:ICMP primary rule scope
func PKScopeOfSgIcmpRules(rules ...model.SgIcmpRule) Scope {
	ret := scopedSgIcmpIdentity{}
	for _, r := range rules {
		id := r.ID()
		ret[id.IdentityHash()] = id
	}
	return ret
}

// PKScopeOfSgSgIcmpRules makes SG-SG:ICMP primary rule scope
func PKScopeOfSgSgIcmpRules(rules ...model.SgSgIcmpRule) Scope {
	ret := scopedSgSgIcmpIdentity{}
	for _, r := range rules {
		id := r.ID()
		ret[id.IdentityHash()] = id
	}
	return ret
}

// PKScopedCidrSgRules makes PROTO:CIDR:SG:TRAFFIC primary rule scope
func PKScopedCidrSgRules(rules ...model.IECidrSgRule) Scope {
	ret := scopedCidrSgRuleIdentity{}
	for _, r := range rules {
		ret[r.ID.IdentityHash()] = r.ID
	}
	return ret
}

// PKScopedCidrSgIcmpRules make ICMP<4|6>:CIDR:SG:TRAFFIC primary rule scope
func PKScopedCidrSgIcmpRules(rules ...model.IECidrSgIcmpRule) Scope {
	ret := scopedCidrSgIcmpRuleIdentity{}
	for _, r := range rules {
		id := r.ID()
		ret[id.IdentityHash()] = id
	}
	return ret
}

// PKScopedSgSgRules makes PROTO:SG-SG:TRAFFIC primary rule scope
func PKScopedSgSgRules(rules ...model.IESgSgRule) Scope {
	ret := scopedSgSgRuleIdentity{}
	for _, r := range rules {
		ret[r.ID.IdentityHash()] = r.ID
	}
	return ret
}

// PKScopedIESgSgRules - primary rule scope
func PKScopedIESgSgRules(rules ...model.IESgSgIcmpRule) Scope {
	ret := scopedIESgSgIcmpRuleIdentity{}
	for _, r := range rules {
		id := r.ID()
		ret[id.IdentityHash()] = id
	}
	return ret
}

func (scopedNot) privateScope()                    {}
func (scopedOr) privateScope()                     {}
func (scopedAnd) privateScope()                    {}
func (noScope) privateScope()                      {}
func (scopedIPs) privateScope()                    {}
func (scopedNetworks) privateScope()               {}
func (scopedSG) privateScope()                     {}
func (scopedSGFrom) privateScope()                 {}
func (scopedSGTo) privateScope()                   {}
func (scopedSGLocal) privateScope()                {}
func (ScopedNetTransport) privateScope()           {}
func (scopedSGRuleIdentity) privateScope()         {}
func (scopedFqdnRuleIdentity) privateScope()       {}
func (scopedSgIcmpIdentity) privateScope()         {}
func (scopedSgSgIcmpIdentity) privateScope()       {}
func (scopedCidrSgRuleIdentity) privateScope()     {}
func (scopedCidrSgIcmpRuleIdentity) privateScope() {}
func (scopedSgSgRuleIdentity) privateScope()       {}
func (scopedIESgSgIcmpRuleIdentity) privateScope() {}

type filterTree[filterArgT any] struct {
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
	var found bool
	sg.Networks.Iterate(func(n model.NetworkName) bool {
		_, found = p.Names[n]
		return !found
	})
	return found
}

func (p scopedNetworks) meta() metaInfo {
	return metaInfo{
		reflect.TypeOf((*model.SecurityGroup)(nil)).Elem(): reflect.ValueOf(p.inSG),

		reflect.TypeOf((*model.Network)(nil)).Elem(): reflect.ValueOf(p.inNetwork),
	}
}

func (p scopedSG) inSG(sg model.SecurityGroup) bool {
	_, ok := p[sg.Name]
	return ok
}

func (p scopedSG) inSgIcmpRule(rule model.SgIcmpRule) bool {
	_, ok := p[rule.Sg]
	return ok
}

func (p scopedSG) inCidrSgRule(rule model.IECidrSgRule) bool {
	_, ok := p[rule.ID.SG]
	return ok
}

func (p scopedSG) inSgSgRule(rule model.IESgSgRule) bool {
	_, ok := p[rule.ID.Sg]
	return ok
}

func (p scopedSG) inIESgSgIcmpRule(rule model.IESgSgIcmpRule) bool {
	_, ok := p[rule.ID().Sg]
	return ok
}

func (p scopedSG) inCidrSgIcmpRule(rule model.IECidrSgIcmpRule) bool {
	_, ok := p[rule.ID().SG]
	return ok
}

func (p scopedSG) meta() metaInfo {
	return metaInfo{
		reflect.TypeOf((*model.SecurityGroup)(nil)).Elem(): reflect.ValueOf(p.inSG),

		reflect.TypeOf((*model.SgIcmpRule)(nil)).Elem(): reflect.ValueOf(p.inSgIcmpRule),

		reflect.TypeOf((*model.IECidrSgRule)(nil)).Elem(): reflect.ValueOf(p.inCidrSgRule),

		reflect.TypeOf((*model.IESgSgRule)(nil)).Elem(): reflect.ValueOf(p.inSgSgRule),

		reflect.TypeOf((*model.IESgSgIcmpRule)(nil)).Elem(): reflect.ValueOf(p.inIESgSgIcmpRule),

		reflect.TypeOf((*model.IECidrSgIcmpRule)(nil)).Elem(): reflect.ValueOf(p.inCidrSgIcmpRule),
	}
}

func (p scopedSGFrom) inSGRule(rule model.SGRule) bool {
	_, ok := p[rule.ID.SgFrom]
	return ok
}

func (p scopedSGFrom) inFqdnRule(rule model.FQDNRule) bool {
	_, ok := p[rule.ID.SgFrom]
	return ok
}

func (p scopedSGFrom) inSgSgIcmpRule(rule model.SgSgIcmpRule) bool {
	_, ok := p[rule.ID().SgFrom]
	return ok
}

func (p scopedSGFrom) meta() metaInfo {
	return metaInfo{
		reflect.TypeOf((*model.SGRule)(nil)).Elem(): reflect.ValueOf(p.inSGRule),

		reflect.TypeOf((*model.FQDNRule)(nil)).Elem(): reflect.ValueOf(p.inFqdnRule),

		reflect.TypeOf((*model.SgSgIcmpRule)(nil)).Elem(): reflect.ValueOf(p.inSgSgIcmpRule),
	}
}

func (p scopedSGTo) inSGRule(rule model.SGRule) bool {
	_, ok := p[rule.ID.SgTo]
	return ok
}

func (p scopedSGTo) inSgSgIcmpRule(rule model.SgSgIcmpRule) bool {
	_, ok := p[rule.ID().SgTo]
	return ok
}

func (p scopedSGTo) meta() metaInfo {
	return metaInfo{
		reflect.TypeOf((*model.SGRule)(nil)).Elem(): reflect.ValueOf(p.inSGRule),

		reflect.TypeOf((*model.SgSgIcmpRule)(nil)).Elem(): reflect.ValueOf(p.inSgSgIcmpRule),
	}
}

func (p scopedSGLocal) inSgSgRule(rule model.IESgSgRule) bool {
	_, ok := p[rule.ID.SgLocal]
	return ok
}

func (p scopedSGLocal) inIESgSgIcmpRule(rule model.IESgSgIcmpRule) bool {
	_, ok := p[rule.ID().SgLocal]
	return ok
}

func (p scopedSGLocal) meta() metaInfo {
	return metaInfo{
		reflect.TypeOf(model.IESgSgRule{}):     reflect.ValueOf(p.inSgSgRule),
		reflect.TypeOf(model.IESgSgIcmpRule{}): reflect.ValueOf(p.inIESgSgIcmpRule),
	}
}

func (p ScopedNetTransport) inSGRule(rule model.SGRule) bool {
	return rule.ID.Transport == model.NetworkTransport(p)
}

func (p ScopedNetTransport) meta() metaInfo {
	return metaInfo{
		reflect.TypeOf((*model.SGRule)(nil)).Elem(): reflect.ValueOf(p.inSGRule),
	}
}

func (p scopedSGRuleIdentity) inSGRule(rule model.SGRule) bool {
	h := rule.ID.IdentityHash()
	_, ok := p[h]
	return ok
}

func (p scopedSGRuleIdentity) meta() metaInfo {
	return metaInfo{
		reflect.TypeOf((*model.SGRule)(nil)).Elem(): reflect.ValueOf(p.inSGRule),
	}
}

func (p scopedFqdnRuleIdentity) inFQDNRule(rule model.FQDNRule) bool {
	h := rule.ID.IdentityHash()
	_, ok := p[h]
	return ok
}

func (p scopedFqdnRuleIdentity) meta() metaInfo {
	return metaInfo{
		reflect.TypeOf((*model.FQDNRule)(nil)).Elem(): reflect.ValueOf(p.inFQDNRule),
	}
}

func (p scopedSgIcmpIdentity) inSgIcmpRule(rule model.SgIcmpRule) bool {
	h := rule.ID().IdentityHash()
	_, ok := p[h]
	return ok
}

func (p scopedSgIcmpIdentity) meta() metaInfo {
	return metaInfo{
		reflect.TypeOf((*model.SgIcmpRule)(nil)).Elem(): reflect.ValueOf(p.inSgIcmpRule),
	}
}

func (p scopedSgSgIcmpIdentity) inSgSgIcmpRule(rule model.SgSgIcmpRule) bool {
	h := rule.ID().IdentityHash()
	_, ok := p[h]
	return ok
}

func (p scopedSgSgIcmpIdentity) meta() metaInfo {
	return metaInfo{
		reflect.TypeOf((*model.SgSgIcmpRule)(nil)).Elem(): reflect.ValueOf(p.inSgSgIcmpRule),
	}
}

func (p scopedCidrSgRuleIdentity) inCidrSgRule(rule model.IECidrSgRule) bool {
	h := rule.ID.IdentityHash()
	_, ok := p[h]
	return ok
}

func (p scopedCidrSgRuleIdentity) meta() metaInfo {
	return metaInfo{
		reflect.TypeOf((*model.IECidrSgRule)(nil)).Elem(): reflect.ValueOf(p.inCidrSgRule),
	}
}

func (p scopedSgSgRuleIdentity) inSgSgRule(rule model.IESgSgRule) bool {
	h := rule.ID.IdentityHash()
	_, ok := p[h]
	return ok
}

func (p scopedSgSgRuleIdentity) meta() metaInfo {
	return metaInfo{
		reflect.TypeOf(model.IESgSgRule{}): reflect.ValueOf(p.inSgSgRule),
	}
}

func (p scopedIESgSgIcmpRuleIdentity) inIESgSgIcmpRule(rule model.IESgSgIcmpRule) bool {
	h := rule.ID().IdentityHash()
	_, ok := p[h]
	return ok
}

func (p scopedIESgSgIcmpRuleIdentity) meta() metaInfo {
	return metaInfo{
		reflect.TypeOf(model.IESgSgIcmpRule{}): reflect.ValueOf(p.inIESgSgIcmpRule),
	}
}

func (p scopedCidrSgIcmpRuleIdentity) inCidrSgIcmpRule(rule model.IECidrSgIcmpRule) bool {
	h := rule.ID().IdentityHash()
	_, ok := p[h]
	return ok
}

func (p scopedCidrSgIcmpRuleIdentity) meta() metaInfo {
	return metaInfo{
		reflect.TypeOf(model.IECidrSgIcmpRule{}): reflect.ValueOf(p.inCidrSgIcmpRule),
	}
}
