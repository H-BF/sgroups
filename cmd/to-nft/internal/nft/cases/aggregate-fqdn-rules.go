package cases

import (
	"context"
	"strings"
	"sync"

	"github.com/H-BF/corlib/pkg/parallel"
	"github.com/H-BF/sgroups/cmd/to-nft/internal/dns"
	conv "github.com/H-BF/sgroups/internal/api/sgroups"
	"github.com/H-BF/sgroups/internal/dict"
	model "github.com/H-BF/sgroups/internal/models/sgroups"

	sgAPI "github.com/H-BF/protos/pkg/api/sgroups"
	"github.com/ahmetb/go-linq/v3"
	"github.com/pkg/errors"
)

type (
	// FQDNRules -
	FQDNRules struct {
		Rules []model.FQDNRule
		A     dict.RBDict[model.FQDN, dns.Addresses]
		AAAA  dict.RBDict[model.FQDN, dns.Addresses]
	}

	// FQDNRulesLoader -
	FQDNRulesLoader struct {
		SGSrv  SGClient
		DnsRes dns.Resolver
	}
)

func (ld FQDNRulesLoader) Load(ctx context.Context, localRules LocalRules) (rr FQDNRules, err error) {
	const api = "FQDNRules/Load"
	defer func() {
		err = errors.WithMessage(err, api)
	}()

	var req sgAPI.FindFqdnRulesReq
	linq.From(localRules.Out).
		Select(func(i any) any {
			return i.(model.SGRule).ID.SgFrom
		}).
		Distinct().ToSlice(&req.SgFrom)
	if len(req.SgFrom) == 0 {
		return rr, nil
	}
	var resp *sgAPI.FqdnRulesResp
	if resp, err = ld.SGSrv.FindFqdnRules(ctx, &req); err != nil {
		return rr, err
	}
	rules := resp.GetRules()
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
		DistinctBy(func(i any) any {
			return strings.ToLower(i.(model.FQDNRule).ID.FqdnTo.String())
		}).
		Select(func(i any) any {
			return i.(model.FQDNRule).ID.FqdnTo
		}).ToSlice(&domains)
	var mx sync.Mutex
	err = parallel.ExecAbstract(len(domains), 8, func(i int) error {
		domain := domains[i].String()
		addrA := ld.DnsRes.A(ctx, domain)
		if addrA.Err != nil {
			return addrA.Err
		}
		/*//
		addrAAAA := ld.DnsRes.AAAA(ctx, domain)
		if addrAAAA.Err != nil {
			return addrAAAA.Err
		}
		*/
		mx.Lock()
		defer mx.Unlock()
		if len(addrA.IPs) > 0 {
			rr.A.Put(domains[i], addrA)
		}
		//if len(addrAAAA.IPs) > 0 {
		//	rr.AAAA.Put(domains[i], addrAAAA)
		//}
		return nil
	})
	return err
}

// SelectForSG -
func (rules FQDNRules) RulesForSG(sgName string) []model.FQDNRule {
	var ret []model.FQDNRule
	linq.From(rules.Rules).
		Where(func(i any) bool {
			return i.(model.FQDNRule).ID.SgFrom == sgName
		}).ToSlice(&ret)
	return ret
}
