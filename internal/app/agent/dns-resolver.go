package agent

import (
	"context"
	"net"
	"time"

	"github.com/H-BF/corlib/pkg/backoff"
	"github.com/H-BF/corlib/pkg/dns"
	config "github.com/H-BF/corlib/pkg/plain-config"
	"github.com/ahmetb/go-linq/v3"
	bf "github.com/cenkalti/backoff/v4"
	"github.com/pkg/errors"
	"go.uber.org/multierr"
)

// DomainAddresses -
type DomainAddresses struct {
	At  time.Time
	TTL time.Duration
	IPs []net.IP
	Err error
}

// DomainAddressQuerier -
type DomainAddressQuerier interface {
	A(ctx context.Context, domain string) DomainAddresses
	AAAA(ctx context.Context, domain string) DomainAddresses
}

// NewDomainAddressQuerier -
func NewDomainAddressQuerier(ctx context.Context) (DomainAddressQuerier, error) {
	var ret domainResolver
	err := ret.init(ctx)
	return ret, err
}

// domainResolver DNS address domainResolver
type domainResolver struct {
	opts []dns.Option
}

var (
	errReadDurationZero   = errors.New("read duration zero")
	errWriteDurationZero  = errors.New("write duration zero")
	errDialDurationZero   = errors.New("dial duration zero")
	errRitryCountZero     = errors.New("retry count zero")
	errRitriesTimeoutZero = errors.New("retiries timeout zero")
	errPortZero           = errors.New("port zero")
	errNoNameservers      = errors.New("no any nameserver is provided")
)

// init inits options from app config
func (r *domainResolver) init(ctx context.Context) (err error) { //nolint:gocyclo
	var bkf backoff.Backoff
	opts := []dns.Option{dns.NoDefNS{}}
	defer func() {
		if err == nil {
			if bkf != nil {
				opts = append(opts, dns.WithBackoff{Backoff: bkf})
			}
			r.opts = opts
		}
	}()
	var errs []error
	errF := func(_ any, e error) func(ignoreNotFound bool) {
		return func(ignoreNotFound bool) {
			if errors.Is(e, config.ErrNotFound) && ignoreNotFound {
				return
			}
			if e != nil {
				errs = append(errs, e)
			}
		}
	}
	errF(DnsNameservers.Value(ctx,
		DnsNameservers.OptSink(func(ips []config.IP) error {
			var o dns.WithNameservers
			linq.From(ips).
				Select(func(i any) any {
					return i.(config.IP).String()
				}).ToSlice(&o)
			if len(o) == 0 {
				return errNoNameservers
			}
			opts = append(opts, o)
			return nil
		}),
	))(false)
	errF(DnsProto.Value(ctx,
		DnsProto.OptSink(func(s string) error {
			switch s {
			case "tcp":
				opts = append(opts, dns.UseTCP{})
			case "udp":
			default:
				return errors.Errorf("unusable proto '%s'", s)
			}
			return nil
		}),
	))(false)
	errF(DnsPort.Value(ctx,
		DnsPort.OptSink(func(u uint16) error {
			if u == 0 {
				return errPortZero
			}
			opts = append(opts, dns.UsePort(u))
			return nil
		}),
	))(false)
	errF(DnsRetriesTmo.Value(ctx,
		DnsRetriesTmo.OptSink(func(d time.Duration) error {
			if d > 0 {
				bkf = backoff.NewConstantBackOff(d)
				return nil
			}
			return errRitriesTimeoutZero
		}),
	))(true)
	errF(DnsRetries.Value(ctx,
		DnsRetries.OptSink(func(u uint8) error {
			if u > 0 {
				if bkf == nil {
					bkf = &bf.ZeroBackOff{}
				}
				bkf = bf.WithMaxRetries(bkf, uint64(u))
				return nil
			}
			return errRitryCountZero
		}),
	))(true)
	errF(DnsDialDuration.Value(ctx,
		DnsDialDuration.OptSink(func(d time.Duration) error {
			if d > 0 {
				opts = append(opts, dns.WithDialDuration(d))
				return nil
			}
			return errDialDurationZero
		}),
	))(true)
	errF(DnsWriteDuration.Value(ctx,
		DnsWriteDuration.OptSink(func(d time.Duration) error {
			if d > 0 {
				opts = append(opts, dns.WithWriteDuration(d))
				return nil
			}
			return errWriteDurationZero
		}),
	))(true)
	errF(DnsReadDuration.Value(ctx,
		DnsReadDuration.OptSink(func(d time.Duration) error {
			if d > 0 {
				opts = append(opts, dns.WithReadDuration(d))
				return nil
			}
			return errReadDurationZero
		}),
	))(true)
	return errors.WithMessage(multierr.Combine(errs...), "dns-resolver/init")
}

// A -
func (r domainResolver) A(ctx context.Context, domain string) (ret DomainAddresses) {
	o := dns.QueryA.Ask(ctx, domain, r.opts...)
	ret.fromDnsAnswer(o)
	return ret
}

// AAAA -
func (r domainResolver) AAAA(ctx context.Context, domain string) (ret DomainAddresses) {
	o := dns.QueryAAAA.Ask(ctx, domain, r.opts...)
	ret.fromDnsAnswer(o)
	return ret
}

func (aa *DomainAddresses) fromDnsAnswer(o dns.AddrAnswer) {
	*aa = DomainAddresses{
		Err: o.Error,
		At:  o.At,
	}
	if o.Error == nil {
		linq.From(o.Addresses).
			Select(func(i any) any {
				return i.(dns.Address).IP
			}).ToSlice(&aa.IPs)
		minTTL, _ := linq.From(o.Addresses).
			Select(func(i any) any {
				return i.(dns.Address).TTL
			}).
			Where(func(i any) bool {
				return i.(uint32) > 0
			}).Min().(uint32)
		aa.TTL = time.Duration(minTTL) * time.Second
	}
}
