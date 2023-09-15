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
	// SG2FQDNRules -
	SG2FQDNRules struct {
		SGs   SGs
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

func (ld FQDNRulesLoader) Load(ctx context.Context, sgs SGs) (rr SG2FQDNRules, err error) {
	const api = "FQDNRules/Load"

	defer func() {
		err = errors.WithMessage(err, api)
	}()

	var req sgAPI.FindFqdnRulesReq
	sgs.Iterate(func(sgName string, _ *SG) bool {
		req.SgFrom = append(req.SgFrom, sgName)
		return true
	})
	if len(req.SgFrom) > 0 {
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
			if sg := sgs.At(m.ID.SgFrom); sg != nil {
				rr.Rules = append(rr.Rules, m)
				_ = rr.SGs.Insert(sg.Name, sg)
			}
		}
		err = ld.fillWithAddresses(ctx, &rr)
	}
	return rr, err
}

func (ld FQDNRulesLoader) fillWithAddresses(ctx context.Context, rr *SG2FQDNRules) (err error) {
	const api = "resolve-addresses"
	const parallelism = 8

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
	err = parallel.ExecAbstract(len(domains), parallelism, func(i int) error {
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
		rr.A.Put(domains[i], addrA)
		//rr.AAAA.Put(domains[i], addrAAAA)
		return nil
	})
	return err
}

// SelectForSG -
func (rules SG2FQDNRules) RulesForSG(sgName string) []model.FQDNRule {
	var ret []model.FQDNRule
	linq.From(rules.Rules).
		Where(func(i any) bool {
			return i.(model.FQDNRule).ID.SgFrom == sgName
		}).ToSlice(&ret)
	return ret
}
