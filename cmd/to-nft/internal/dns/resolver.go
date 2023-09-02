package dns

import (
	"context"
	"net"
	"time"

	"github.com/H-BF/sgroups/cmd/to-nft/internal"
	"github.com/H-BF/sgroups/internal/config"
	"github.com/H-BF/sgroups/internal/dns"

	"github.com/H-BF/corlib/pkg/backoff"

	"github.com/ahmetb/go-linq/v3"
	bf "github.com/cenkalti/backoff/v4"
	"github.com/pkg/errors"
	"go.uber.org/multierr"
)

// Addresses -
type Addresses struct {
	Domain       string
	ExpiredAfter *time.Time
	IPs          []net.IP
	Err          error
}

// Resolver -
type Resolver interface {
	A(ctx context.Context, domain string) Addresses
	AAAA(ctx context.Context, domain string) Addresses
}

// NewResolver -
func NewResolver(ctx context.Context) (Resolver, error) {
	var ret resolver
	err := ret.init(ctx)
	return ret, err
}

// resolver DNS address resolver
type resolver struct {
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
func (r *resolver) init(ctx context.Context) (err error) {
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
	errH := func(_ any, e error) func(ignoreNotFound bool) {
		return func(ignoreNotFound bool) {
			if errors.Is(e, config.ErrNotFound) && ignoreNotFound {
				return
			}
			if e != nil {
				errs = append(errs, e)
			}
		}
	}
	errH(internal.DnsNameservers.Value(ctx,
		internal.DnsNameservers.OptSink(func(ips []config.IP) error {
			var o dns.WithNameservers
			linq.From(ips).
				Select(func(i any) any {
					return i.(net.IP).String()
				}).ToSlice(&o)
			if len(o) == 0 {
				return errNoNameservers
			}
			opts = append(opts, o)
			return nil
		}),
	))(false)
	errH(internal.DnsProto.Value(ctx,
		internal.DnsProto.OptSink(func(s string) error {
			switch s {
			case "tcp":
				opts = append(opts, dns.UseTCP{})
			case "udp":
			default:
				return errors.Errorf("unusable proto (%s)", s)
			}
			return nil
		}),
	))(false)
	errH(internal.DnsPort.Value(ctx,
		internal.DnsPort.OptSink(func(u uint16) error {
			if u == 0 {
				return errPortZero
			}
			opts = append(opts, dns.UsePort(u))
			return nil
		}),
	))(false)
	errH(internal.DnsRetriesTmo.Value(ctx,
		internal.DnsRetriesTmo.OptSink(func(d time.Duration) error {
			if d > 0 {
				bkf = backoff.NewConstantBackOff(d)
				return nil
			}
			return errRitriesTimeoutZero
		}),
	))(true)
	errH(internal.DnsRetries.Value(ctx,
		internal.DnsRetries.OptSink(func(u uint8) error {
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
	errH(internal.DnsDialDuration.Value(ctx,
		internal.DnsDialDuration.OptSink(func(d time.Duration) error {
			if d > 0 {
				opts = append(opts, dns.WithDialDuration(d))
				return nil
			}
			return errDialDurationZero
		}),
	))(true)
	errH(internal.DnsWriteDuration.Value(ctx,
		internal.DnsWriteDuration.OptSink(func(d time.Duration) error {
			if d > 0 {
				opts = append(opts, dns.WithWriteDuration(d))
				return nil
			}
			return errWriteDurationZero
		}),
	))(true)
	errH(internal.DnsReadDuration.Value(ctx,
		internal.DnsReadDuration.OptSink(func(d time.Duration) error {
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
func (r resolver) A(ctx context.Context, domain string) (ret Addresses) {
	o := dns.QueryA.Ask(ctx, domain, r.opts...)
	ret.fromDnsAnswer(o)
	return ret
}

// AAAA -
func (r resolver) AAAA(ctx context.Context, domain string) (ret Addresses) {
	o := dns.QueryAAAA.Ask(ctx, domain, r.opts...)
	ret.fromDnsAnswer(o)
	return ret
}

func (aa *Addresses) fromDnsAnswer(o dns.AddrAnswer) {
	*aa = Addresses{}
	aa.Domain = o.Domain
	if o.Error != nil {
		aa.Err = o.Error
		return
	}
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
	if minTTL > 0 {
		d := time.Now().Add(time.Duration(minTTL) * time.Second)
		aa.ExpiredAfter = &d
	}
}
