package cases

import (
	"context"
	"sync"

	"github.com/H-BF/sgroups/cmd/to-nft/internal"
	conv "github.com/H-BF/sgroups/internal/api/sgroups"
	model "github.com/H-BF/sgroups/internal/models/sgroups"

	"github.com/H-BF/corlib/pkg/dict"
	"github.com/H-BF/corlib/pkg/parallel"
	sgAPI "github.com/H-BF/protos/pkg/api/sgroups"
	"github.com/ahmetb/go-linq/v3"
	"github.com/pkg/errors"
)

type (
	// SG2FQDNRules -
	SG2FQDNRules struct {
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
	if !rules.FQDNs.Eq(&other.FQDNs) {
		return false
	}
	var l, r dict.HDict[string, *model.FQDNRule]
	for i := range rules.Rules {
		a := &rules.Rules[i]
		l.Insert(a.ID.String(), a)
	}
	for i := range other.Rules {
		a := &other.Rules[i]
		r.Insert(a.ID.String(), a)
	}
	return l.Eq(&r, func(vL, vR *model.FQDNRule) bool {
		return vL.IsEq(*vR)
	})
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
			if sgs.At(m.ID.SgFrom) != nil {
				rules.Rules = append(rules.Rules, m)
				rules.FQDNs.Insert(m.ID.FqdnTo)
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

// UpdAAAA -
func (r *ResolvedFQDN) UpdAAAA(domain model.FQDN, addr internal.DomainAddresses) {
	r.Lock()
	defer r.Unlock()
	r.AAAA.Put(domain, addr)
}

// Resolve -
func (r *ResolvedFQDN) Resolve(ctx context.Context, rules SG2FQDNRules, dnsRes internal.DomainAddressQuerier) {
	const parallelism = 7

	type item = struct {
		domain model.FQDN
		up     func(model.FQDN, internal.DomainAddresses)
		re     func(context.Context, string) internal.DomainAddresses
	}
	var items []item
	rules.FQDNs.Iterate(func(k model.FQDN) bool {
		items = append(items,
			item{domain: k, up: r.UpdA, re: dnsRes.A},
			//item{domain: k, up: r.UpdAAAA, re: dnsRes.AAAA},
		)
		return true
	})
	_ = parallel.ExecAbstract(len(items), parallelism, func(i int) error {
		item := items[i]
		res := item.re(ctx, item.domain.String())
		item.up(item.domain, res)
		return nil
	})
}
