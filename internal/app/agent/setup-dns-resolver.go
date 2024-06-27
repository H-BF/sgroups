package agent

import (
	"context"

	"github.com/H-BF/corlib/pkg/atomic"
)

// GetDnsResolver -
func GetDnsResolver() DomainAddressQuerier {
	ret, ok := appDnsResolver.Load()
	if !ok {
		panic("Need call 'SetupDnsResolver'")
	}
	return ret
}

// SetupDnsResolver -
func SetupDnsResolver(ctx context.Context) error {
	dnsResolver, err := NewDomainAddressQuerier(ctx)
	if err != nil {
		return err
	}
	cached := NewDomainAddressQuerierCache(dnsResolver)
	appDnsResolver.Store(cached, func(o DomainAddressQuerierCacheWrapper) {
		_ = o.Close()
	})
	return nil
}

var (
	appDnsResolver atomic.Value[DomainAddressQuerierCacheWrapper]
)
