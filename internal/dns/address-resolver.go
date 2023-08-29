package dns

import (
	"context"
	"fmt"
	"net"
	"strconv"

	"github.com/ahmetb/go-linq/v3"
	"github.com/miekg/dns"
	"github.com/pkg/errors"
	"go.uber.org/multierr"
)

var (
	// QueryA -
	QueryA AddressResolver = queryAddress[typeA]{}

	// QueryAAAA -
	QueryAAA AddressResolver = queryAddress[typeAAAA]{}

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
		Domain    string
		Addresses []Address
		Error     error
	}

	// Address -
	Address struct {
		TTL uint32
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
	var errs []error
	var succeeded int
	nn := int(-1)
	linq.From(nss).
		Where(func(_ any) bool {
			return nn <= 0 || !haveCancelledOrDeadline(errs[nn-1])
		}).
		Select(func(i any) any {
			nn++
			v := i.(string)
			msg := h.makeMsq(q)
			n := tern(net.ParseIP(v) != nil,
				net.JoinHostPort(v, strconv.Itoa(int(h.port))),
				fmt.Sprintf("%s:%v", dns.Fqdn(v), h.port))
			var r retType
			if r.m, _, r.e = c.ExchangeContext(ctx, msg, n); r.e != nil {
				errs = append(errs, errors.WithMessagef(r.e, "use-ns(%s)", v))
			} else if r.m.Rcode == dns.RcodeSuccess {
				succeeded++
			}
			return r
		}).
		Where(func(i any) bool {
			v := i.(retType)
			return v.e == nil && v.m.Rcode == dns.RcodeSuccess &&
				len(v.m.Answer) > 0
		}).
		Take(1).
		SelectMany(func(i any) linq.Query {
			rrs := i.(retType).m.Answer
			return linq.From(AddrT{}.rr2addr(rrs))
		}).ToSlice(&ret.Addresses)

	ret.Error = tern(succeeded == 0, multierr.Combine(errs...), nil)
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
