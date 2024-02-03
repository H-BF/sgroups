package cases

import (
	"context"
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
		FQDNs dict.RBSet[model.FQDN]
	}

	// ResolvedFQDN -
	ResolvedFQDN struct {
		sync.RWMutex
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

// Load -
func (rules *SG2FQDNRules) Load(ctx context.Context, SGSrv SGClient, sgs SGs) (err error) {
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
		if resp, err = SGSrv.FindFqdnRules(ctx, &req); err != nil {
			return err
		}
		rr := resp.GetRules()
		for _, r := range rr {
			var m model.FQDNRule
			if m, err = conv.Proto2ModelFQDNRule(r); err != nil {
				return err
			}
			if sg := sgs.At(m.ID.SgFrom); sg != nil {
				rules.Rules = append(rules.Rules, m)
				rules.FQDNs.Insert(m.ID.FqdnTo)
				_ = rules.SGs.Insert(sg.Name, sg)
			}
		}
	}
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

// UpdA -
func (r *ResolvedFQDN) UpdA(domain model.FQDN, addr internal.DomainAddresses) {
	r.Lock()
	defer r.Unlock()
	r.A.Put(domain, addr)
}

// UpdAAA -
func (r *ResolvedFQDN) UpdAAA(domain model.FQDN, addr internal.DomainAddresses) {
	r.Lock()
	defer r.Unlock()
	r.AAAA.Put(domain, addr)
}

// Resolve -
func (r *ResolvedFQDN) Resolve(ctx context.Context, domains []model.FQDN, dnsRes internal.DomainAddressQuerier) {
	const parallelism = 7

	_ = parallel.ExecAbstract(len(domains), parallelism, func(i int) error {
		domain := domains[i].String()
		addrA := dnsRes.A(ctx, domain)
		r.UpdA(domains[i], addrA)
		//addrAAAA := ld.DnsRes.AAAA(ctx, domain)
		//r.UpdAAA(domains[i], addrAAAA)
		return nil
	})
}
