package agent

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/H-BF/corlib/pkg/atomic"
	"github.com/H-BF/corlib/pkg/dict"
)

// NewDomainAddressQuerierCache -
func NewDomainAddressQuerierCache(o DomainAddressQuerier) DomainAddressQuerierCacheWrapper {
	ret := domainAddressQuerierCacheWrappee{wrapped: o}
	ret.cache.Store(new(daqcDict), nil)
	return &ret
}

// DomainAddressQuerierCacheWrapper -
type DomainAddressQuerierCacheWrapper interface {
	A(ctx context.Context, domain string) DomainAddresses
	AAAA(ctx context.Context, domain string) DomainAddresses
	Close() error
}

var (
	// ErrDomainAddressQuerierCacheClosed -
	ErrDomainAddressQuerierCacheClosed = errors.New("dns address querier cache is closed")
)

type daqcKey struct {
	ipV    uint8
	domain string
}

type daqcVal struct {
	sync.Once
	addr DomainAddresses
}

type daqcDict = dict.HDict[daqcKey, *daqcVal]

type domainAddressQuerierCacheWrappee struct {
	sync.Mutex
	wrapped DomainAddressQuerier
	cache   atomic.Value[*daqcDict]
}

func (c *domainAddressQuerierCacheWrappee) makeKey(ipV uint8, dom string) daqcKey {
	return daqcKey{
		ipV:    ipV,
		domain: strings.ToLower(dom),
	}
}

// A -
func (c *domainAddressQuerierCacheWrappee) A(ctx context.Context, domain string) DomainAddresses {
	const ipv = 4
	return c.doAsk(ctx, ipv, domain)
}

// AAAA -
func (c *domainAddressQuerierCacheWrappee) AAAA(ctx context.Context, domain string) DomainAddresses {
	const ipv = 6
	return c.doAsk(ctx, ipv, domain)
}

// Close -
func (c *domainAddressQuerierCacheWrappee) Close() error {
	c.cache.Clear(func(o *daqcDict) {
		o.Clear()
	})
	return nil
}

func (c *domainAddressQuerierCacheWrappee) doAsk(ctx context.Context, ipV uint8, domain string) DomainAddresses {
	const (
		ip4 = 4
		ip6 = 6
	)
	switch ipV {
	case ip4, ip6:
	default:
		panic(fmt.Errorf("used wrong ipV(%v)", ipV))
	}
	cache, _ := c.cache.Load()
	if cache == nil {
		return DomainAddresses{Err: ErrDomainAddressQuerierCacheClosed}
	}
	key := c.makeKey(ipV, domain)
	c.Lock()
	v := cache.At(key)
	if v == nil || (!v.addr.At.Equal(time.Time{}) && time.Since(v.addr.At) >= v.addr.TTL) {
		v = new(daqcVal)
		cache.Put(key, v)
	}
	c.Unlock()
	v.Do(func() {
		var a DomainAddresses
		switch ipV {
		case ip4:
			a = c.wrapped.A(ctx, domain)
		case ip6:
			a = c.wrapped.AAAA(ctx, domain)
		}
		c.Lock()
		defer c.Unlock()
		v.addr = a
		if v.addr.Err != nil || len(v.addr.IPs) == 0 {
			cache.Del(key)
		}
	})
	return v.addr
}
