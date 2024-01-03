package cases

import (
	"context"
	"strings"
	"sync"

	"github.com/H-BF/corlib/pkg/parallel"
	"github.com/H-BF/sgroups/cmd/to-nft/internal"
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

		Resolved *ResolvedFQDN
	}

	// FQDNRulesLoader -
	FQDNRulesLoader struct {
		SGSrv  SGClient
		DnsRes internal.DomainAddressQuerier
	}

	// ResolvedFQDN -
	ResolvedFQDN struct {
		sync.Mutex
		A    dict.RBDict[model.FQDN, internal.DomainAddresses]
		AAAA dict.RBDict[model.FQDN, internal.DomainAddresses]
	}
)

// IsEq -
func (rules *SG2FQDNRules) IsEq(other SG2FQDNRules) bool {
	eq := rules.SGs.IsEq(other.SGs)
	if eq {
		var l, r dict.HDict[string, *model.FQDNRule]
		if len(rules.Rules) == len(other.Rules) {
			for i := range rules.Rules {
				a := &rules.Rules[i]
				b := &other.Rules[i]
				l.Insert(a.ID.String(), a)
				r.Insert(a.ID.String(), b)
			}
		}
		eq = l.Eq(&r, func(vL, vR *model.FQDNRule) bool {
			return vL.IsEq(*vR)
		})
	}
	return eq
}

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
	rr.Resolved = new(ResolvedFQDN)
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
		ld.resolveDomainAddresses(ctx, &rr)
	}
	return rr, err
}

func (ld FQDNRulesLoader) resolveDomainAddresses(ctx context.Context, rr *SG2FQDNRules) {
	const parallelism = 8

	var domains []model.FQDN
	linq.From(rr.Rules).
		DistinctBy(func(i any) any {
			return strings.ToLower(i.(model.FQDNRule).ID.FqdnTo.String())
		}).
		Select(func(i any) any {
			return i.(model.FQDNRule).ID.FqdnTo
		}).ToSlice(&domains)

	resolved := rr.Resolved
	if ld.DnsRes == nil {
		for i := range domains {
			resolved.A.Put(domains[i], internal.DomainAddresses{})
			//resolved.AAAA.Put(domains[i], internal.DomainAddresses{})
		}
	} else {
		_ = parallel.ExecAbstract(len(domains), parallelism, func(i int) error {
			domain := domains[i].String()
			addrA := ld.DnsRes.A(ctx, domain)
			//addrAAAA := ld.DnsRes.AAAA(ctx, domain)
			resolved.Lock()
			resolved.A.Put(domains[i], addrA)
			//resolved.AAAA.Put(domains[i], addrAAAA)
			resolved.Unlock()
			return nil
		})
	}
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
