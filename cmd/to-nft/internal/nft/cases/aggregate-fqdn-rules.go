package cases

import (
	"context"
	"strings"

	"github.com/H-BF/corlib/pkg/parallel"
	"github.com/H-BF/sgroups/cmd/to-nft/internal/dns"
	conv "github.com/H-BF/sgroups/internal/api/sgroups"
	"github.com/H-BF/sgroups/internal/dict"
	model "github.com/H-BF/sgroups/internal/models/sgroups"

	sgAPI "github.com/H-BF/protos/pkg/api/sgroups"
	"github.com/ahmetb/go-linq/v3"
	"github.com/pkg/errors"
)

// FQDNRules -
type FQDNRules struct {
	Rules []model.FQDNRule
	A     dict.RBDict[model.FQDN, dns.Addresses]
	AAAA  dict.RBDict[model.FQDN, dns.Addresses]
}

// FQDNRulesLoader -
type FQDNRulesLoader struct {
	SGSrv  SGClient
	DnsRes dns.Resolver
}

func (ld FQDNRulesLoader) Load(ctx context.Context, localSGs SGs) (rr FQDNRules, err error) {
	const api = "FQDNRules/Load"
	defer func() {
		err = errors.WithMessage(err, api)
	}()

	var req sgAPI.FindFqdnRulesReq
	linq.From(localSGs).
		Select(func(i any) any {
			return i.(linq.KeyValue).Key.(string)
		}).ToSlice(&req.SgFrom)
	if len(req.SgFrom) == 0 {
		return rr, nil
	}
	var resp *sgAPI.FqdnRulesResp
	if resp, err = ld.SGSrv.FindFqdnRules(ctx, &req); err != nil {
		return rr, err
	}
	rules := resp.GetRules()
	rr.Rules = make([]model.FQDNRule, 0, len(rules))
	for _, r := range rules {
		var m model.FQDNRule
		if m, err = conv.Proto2ModelFQDNRule(r); err != nil {
			return rr, err
		}
		rr.Rules = append(rr.Rules, m)
	}
	err = ld.fillWithAddresses(ctx, &rr)
	return rr, err
}

func (ld FQDNRulesLoader) fillWithAddresses(ctx context.Context, rr *FQDNRules) (err error) {
	const api = "resolve-addresses"
	defer func() {
		err = errors.WithMessage(err, api)
	}()
	var domains []model.FQDN
	linq.From(rr.Rules).
		Select(func(i any) any {
			return i.(model.FQDNRule).ID.FqdnTo
		}).
		DistinctBy(func(i any) any {
			return strings.ToLower(i.(model.FQDN).String())
		}).ToSlice(&domains)
	rA := make([]dns.Addresses, len(domains))
	rAAAA := make([]dns.Addresses, len(domains))
	err = parallel.ExecAbstract(len(domains), 8, func(i int) error {
		domain := domains[i].String()
		if rA[i] = ld.DnsRes.A(ctx, domain); rA[i].Err != nil {
			return rA[i].Err
		}
		rAAAA[i] = ld.DnsRes.AAAA(ctx, domain)
		return rAAAA[i].Err
	})
	if err != nil {
		return err
	}
	for i, dm := range domains {
		if x := rA[i]; len(x.IPs) > 0 {
			rr.A.Put(dm, x)
		}
		if x := rAAAA[i]; len(x.IPs) > 0 {
			rr.A.Put(dm, x)
		}
	}
	return nil
}
