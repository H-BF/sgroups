package dns

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	bkf "github.com/H-BF/corlib/pkg/backoff"
	"github.com/ahmetb/go-linq/v3"
	"github.com/miekg/dns"
	"github.com/pkg/errors"
	"go.uber.org/multierr"
)

var (
	// QueryA -
	QueryA AddressResolver = queryAddress[typeA]{}

	// QueryAAAA -
	QueryAAAA AddressResolver = queryAddress[typeAAAA]{}

	// ErrNoAnyNs - no any nameserver is used
	ErrNoAnyNs = errors.New("no any nameserver is used")
)

type (
	// AddressResolver address resolver interface
	AddressResolver interface {
		Ask(ctx context.Context, domain string, opts ...Option) AddrAnswer
	}

	// AddrAnswer -
	AddrAnswer struct {
		At        time.Time
		Domain    string
		Addresses []Address
		Error     error
	}

	// Address -
	Address struct {
		TTL uint32 //time to live in seconds
		IP  net.IP
	}

	typeA struct{}

	typeAAAA struct{}

	addrTag interface {
		queryType() uint16
		rr2addr([]dns.RR) []Address
		typeA | typeAAAA
	}
	queryAddress[AddrT addrTag] struct{}
)

// Ask asks nameserver(s) for IP addresses related to 'domain' name
func (queryAddress[AddrT]) Ask(ctx context.Context, domain string, opts ...Option) (ret AddrAnswer) {
	const api = "dns-address-resolver"

	ret.Domain = domain
	ret.At = time.Now()
	defer func() {
		ret.Error = errors.WithMessage(ret.Error, api)
	}()
	q := dns.Question{
		Name:   dns.Fqdn(domain),
		Qclass: dns.ClassINET,
		Qtype:  AddrT{}.queryType(),
	}
	var h queryHelper
	var c *dns.Client
	h.init(opts...)
	nss := h.nsList()
	if len(nss) == 0 {
		ret.Error = ErrNoAnyNs
		return ret
	}
	if c, ret.Error = h.buildClient(); ret.Error != nil {
		return ret
	}
	type retType = struct {
		m *dns.Msg
		e error
	}
	for {
		var errs []error
		for i := range nss {
			msg := h.makeMsq(q)
			ns := nss[i]
			ep := tern(net.ParseIP(ns) != nil,
				net.JoinHostPort(ns, strconv.Itoa(int(h.port))),
				fmt.Sprintf("%s:%v", ns, h.port))
			ret.At = time.Now()
			var r retType
			r.m, _, r.e = c.ExchangeContext(ctx, msg, ep)
			if r.e == nil && r.m.Rcode != dns.RcodeSuccess {
				r.e = errors.Errorf("ret-code(%v)", r.m.Rcode)
			}
			if r.e == nil {
				ret.At = time.Now()
				ret.Addresses = AddrT{}.rr2addr(r.m.Answer)
				return ret
			}
			errs = append(errs, errors.WithMessagef(r.e, "use-ns(%s)", ns))
			if haveCancelledOrDeadline(r.e) {
				ret.Error = multierr.Combine(errs...)
				return ret
			}
		}
		nxt := h.backoff.NextBackOff()
		if nxt == bkf.Stop {
			ret.Error = multierr.Combine(errs...)
		} else if nxt > 100*time.Millisecond {
			select {
			case <-time.After(nxt):
				continue
			case <-ctx.Done():
				ret.Error = multierr.Combine(append(errs, ctx.Err())...)
			}
		} else {
			select {
			case <-ctx.Done():
				ret.Error = multierr.Combine(append(errs, ctx.Err())...)
			default:
				continue
			}
		}
		break
	}
	return ret
}

func (typeA) queryType() uint16 {
	return dns.TypeA
}

func (typeA) rr2addr(rrs []dns.RR) []Address {
	return rr2addr[*dns.A](rrs)
}

func (typeAAAA) queryType() uint16 {
	return dns.TypeAAAA
}

func (typeAAAA) rr2addr(rrs []dns.RR) []Address {
	return rr2addr[*dns.AAAA](rrs)
}

func haveCancelledOrDeadline(errs ...error) bool {
	return linq.From(errs).
		Where(func(i any) bool {
			e := i.(error)
			return errors.Is(e, context.Canceled) ||
				errors.Is(e, context.DeadlineExceeded)
		}).First() != nil
}

func rr2addr[addrT interface{ *dns.A | *dns.AAAA }](rrs []dns.RR) []Address {
	type addr = struct {
		Address
		ok bool
	}
	ret := make([]Address, 0, len(rrs))
	linq.From(rrs).
		Select(func(v any) any {
			switch any(addrT(nil)).(type) {
			case *dns.A:
				if o, _ := v.(*dns.A); o != nil {
					return addr{
						Address: Address{
							TTL: o.Hdr.Ttl,
							IP:  o.A,
						},
						ok: true,
					}
				}
			case *dns.AAAA:
				if o, _ := v.(*dns.AAAA); o != nil {
					return addr{
						Address: Address{
							TTL: o.Hdr.Ttl,
							IP:  o.AAAA,
						},
						ok: true,
					}
				}
			}
			return addr{}
		}).
		Where(func(i any) bool {
			return i.(addr).ok
		}).
		Select(func(i any) any {
			return i.(addr).Address
		}).ToSlice(&ret)
	return ret
}
