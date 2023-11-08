package fixtures

import (
	"reflect"
	"sync"

	sgAPI "github.com/H-BF/sgroups/internal/api/sgroups"
	"github.com/H-BF/sgroups/internal/dict"
	domain "github.com/H-BF/sgroups/internal/models/sgroups"

	"github.com/H-BF/corlib/pkg/functional"
	protos "github.com/H-BF/protos/pkg/api/sgroups"
)

type (
	// DomainRC -
	DomainRC interface {
		domain.Network | domain.SecurityGroup |
			domain.SGRule | domain.FQDNRule
	}

	// DomainRcList -
	DomainRcList[T DomainRC] []T
)

// ToDict -
func (lst DomainRcList[T]) ToDict() (ret dict.HDict[string, T]) {
	for _, it := range lst {
		ret.Put(extractKey(it), it)
	}
	return ret
}

// AnyIn -
func (lst DomainRcList[T]) AnyIn(other DomainRcList[T], fullCompare bool) bool {
	if len(lst) == 0 {
		return false
	}
	x := other.ToDict()
	for _, it := range lst {
		v, ok := x.Get(extractKey(it))
		if ok && fullCompare {
			ok = isEQ(it, v)
		}
		if ok {
			return true
		}
	}
	return false
}

// AllIn -
func (lst DomainRcList[T]) AllIn(other DomainRcList[T], fullCompare bool) bool {
	x := other.ToDict()
	for _, it := range lst {
		v, ok := x.Get(extractKey(it))
		if ok && fullCompare {
			ok = isEQ(it, v)
		}
		if !ok {
			return false
		}
	}
	return true
}

var (
	ensureReg    sync.Once
	allCallables dict.HDict[reflect.Type, functional.Callable]
)

func extractKey[T any](obj T) string {
	ensureReg.Do(regHelpers)
	ty := reflect.TypeOf(extractKey[T])
	c := allCallables.At(ty)
	ret := functional.MustInvoke(c, obj)
	return ret[0].(string)
}

func isEQ[T any](l, r T) bool {
	ensureReg.Do(regHelpers)
	ty := reflect.TypeOf(isEQ[T])
	c := allCallables.At(ty)
	ret := functional.MustInvoke(c, l, r)
	return ret[0].(bool)
}

func proto2domain[P BackendRC, Ret any](msg *P, r *Ret) {
	ensureReg.Do(regHelpers)
	ty := reflect.TypeOf(proto2domain[P, Ret])
	c := allCallables.At(ty)
	functional.MustInvokeNoResult(c, msg, r)
}

func regKeyExtractor[T any](f func(T) string) {
	allCallables.Put(reflect.TypeOf(f), functional.MustCallableOf(f))
}

func regIsEQ[T any](f func(l, r T) bool) {
	allCallables.Put(reflect.TypeOf(f), functional.MustCallableOf(f))
}

func regProto2domain[P BackendRC, Ret any](f func(*P, *Ret)) {
	allCallables.Put(reflect.TypeOf(f), functional.MustCallableOf(f))
}

func regHelpers() {
	// ---------------------- RC Network ---------------------
	regKeyExtractor(func(m domain.Network) string {
		return m.Name
	})
	regIsEQ(func(l, r domain.Network) bool {
		return l.IsEq(r)
	})
	regProto2domain(func(p *protos.Network, r *domain.Network) {
		var e error
		if *r, e = sgAPI.Proto2ModelNetwork(p); e != nil {
			panic(e)
		}
	})

	// ---------------------- RC SecurityGroup ---------------------
	regKeyExtractor(func(m domain.SecurityGroup) string {
		return m.Name
	})
	regIsEQ(func(l, r domain.SecurityGroup) bool {
		return l.IsEq(r)
	})
	regProto2domain(func(p *protos.SecGroup, r *domain.SecurityGroup) {
		var e error
		if *r, e = sgAPI.Proto2ModelSG(p); e != nil {
			panic(e)
		}
	})

	// ---------------------- RC SGRule ---------------------
	regKeyExtractor(func(m domain.SGRule) string {
		return m.ID.String()
	})
	regIsEQ(func(l, r domain.SGRule) bool {
		return l.IsEq(r)
	})
	regProto2domain(func(p *protos.Rule, r *domain.SGRule) {
		var e error
		if *r, e = sgAPI.Proto2ModelSGRule(p); e != nil {
			panic(e)
		}
	})

	// ---------------------- RC FQDNRule ---------------------
	regKeyExtractor(func(m domain.FQDNRule) string {
		return m.ID.String()
	})
	regIsEQ(func(l, r domain.FQDNRule) bool {
		return l.IsEq(r)
	})
	regProto2domain(func(p *protos.FqdnRule, r *domain.FQDNRule) {
		var e error
		if *r, e = sgAPI.Proto2ModelFQDNRule(p); e != nil {
			panic(e)
		}
	})
}
