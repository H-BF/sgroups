package cases

import (
	"context"
	"net"
	"time"

	"github.com/H-BF/sgroups/cmd/to-nft/internal/host"
	model "github.com/H-BF/sgroups/internal/models/sgroups"

	"github.com/H-BF/corlib/logger"
	"github.com/H-BF/corlib/pkg/dict"
	"github.com/pkg/errors"
)

type (
	// LocalData are used by agent to build Host Based Firewall rules
	LocalData struct {
		LocalSGs          SGs
		SG2SGRules        SG2SGRules
		SG2FQDNRules      SG2FQDNRules
		SgIcmpRules       SgIcmpRules
		SgSgIcmpRules     SgSgIcmpRules
		SgIeSgIcmpRules   SgIeSgIcmpRules
		CidrSgRules       CidrSgRules
		SgIeSgRules       SgIeSgRules
		IECidrSgIcmpRules IECidrSgIcmpRules
		Networks          SGsNetworks

		ResolvedFQDN *ResolvedFQDN
		SyncStatus   model.SyncStatus
	}

	// LocalDataLoader
	LocalDataLoader struct {
		SyncStatus      model.SyncStatus
		MaxLoadDiration time.Duration
	}
)

func (ld *LocalData) allUsedSGs() []SgName {
	var d dict.HSet[SgName]
	ld.SG2SGRules.Rules.Iterate(func(k model.SGRuleIdentity, _ *model.SGRule) bool {
		d.PutMany(k.SgFrom, k.SgTo)
		return true
	})
	for _, r := range ld.SG2FQDNRules.Rules {
		d.Insert(r.ID.SgFrom)
	}
	ld.SgIcmpRules.Rules.Iterate(func(k model.SgIcmpRuleID, _ *model.SgIcmpRule) bool {
		d.Insert(k.Sg)
		return true
	})
	ld.SgSgIcmpRules.Rules.Iterate(func(k model.SgSgIcmpRuleID, _ *model.SgSgIcmpRule) bool {
		d.PutMany(k.SgFrom, k.SgTo)
		return true
	})
	ld.SgIeSgIcmpRules.Rules.Iterate(func(k model.IESgSgIcmpRuleID, _ *model.IESgSgIcmpRule) bool {
		d.PutMany(k.Sg, k.SgLocal)
		return true
	})
	ld.CidrSgRules.Rules.Iterate(func(k model.IECidrSgRuleIdenity, _ *model.IECidrSgRule) bool {
		d.Insert(k.SG)
		return true
	})
	ld.SgIeSgRules.Rules.Iterate(func(k model.IESgSgRuleIdentity, _ *model.IESgSgRule) bool {
		d.PutMany(k.Sg, k.SgLocal)
		return true
	})
	ld.IECidrSgIcmpRules.Rules.Iterate(func(k model.IECidrSgIcmpRuleID, _ *model.IECidrSgIcmpRule) bool {
		d.Insert(k.SG)
		return true
	})
	return d.Values()
}

func (ld *LocalData) nonLocalSGs() []SgName {
	all := ld.allUsedSGs()
	ret := all[:0]
	for _, s := range all {
		if ld.LocalSGs.At(s) == nil {
			ret = append(ret, s)
		}
	}
	return ret
}

// IsEq checks wether this object is equal the other one
// here we compare only rules and networks
func (ld *LocalData) IsEq(other LocalData) bool {
	eq := ld.SG2SGRules.IsEq(other.SG2SGRules)
	if eq {
		eq = ld.SG2FQDNRules.IsEq(other.SG2FQDNRules)
	}
	if eq {
		eq = ld.SgIcmpRules.IsEq(other.SgIcmpRules)
	}
	if eq {
		eq = ld.SgSgIcmpRules.IsEq(other.SgSgIcmpRules)
	}
	if eq {
		eq = ld.SgIeSgIcmpRules.IsEq(other.SgIeSgIcmpRules)
	}
	if eq {
		eq = ld.CidrSgRules.IsEq(other.CidrSgRules)
	}
	if eq {
		eq = ld.SgIeSgRules.IsEq(other.SgIeSgRules)
	}
	if eq {
		eq = ld.Networks.IsEq(other.Networks)
	}
	if eq {
		eq = ld.IECidrSgIcmpRules.IsEq(other.IECidrSgIcmpRules)
	}
	return eq
}

// Load -
func (loader *LocalDataLoader) Load(ctx context.Context, client SGClient, ncnf host.NetConf) (res LocalData, err error) {
	defer func() {
		err = errors.WithMessage(err, "LocalData/Load")
	}()

	var locIPs []net.IP
	{
		v4, v6 := ncnf.LocalIPs()
		locIPs = append(append(locIPs, v4...), v6...)
	}
	res.SyncStatus = loader.SyncStatus
	log := logger.FromContext(ctx)
	if len(locIPs) == 0 {
		return res, errors.New("no any host IP is provided")
	}
	if loader.MaxLoadDiration > 0 {
		ctx1, cancel := context.WithTimeout(ctx, loader.MaxLoadDiration)
		defer cancel()
		ctx = ctx1
	}

	log.Debugf("loading local SG(s) from host local IP(s) %s ...", locIPs)
	if err = res.LocalSGs.LoadFromIPs(ctx, client, locIPs); err != nil {
		return res, err
	}
	log.Debugf("found local SG(s) %s", res.LocalSGs.Names())
	if res.LocalSGs.Len() == 0 {
		log.Warn("no any rule will search cause no any local SG is found")
		return res, err
	}

	log.Debugw("loading netwirks from local SG(s)...")
	if err = res.Networks.Load(ctx, client, res.LocalSGs); err != nil {
		return res, err
	}

	log.Debugw("loading SG-SG rules...")
	if err = res.SG2SGRules.Load(ctx, client, res.LocalSGs); err != nil {
		return res, err
	}

	log.Debugw("loading SG-ICMP rules...")
	if err = res.SgIcmpRules.Load(ctx, client, res.LocalSGs); err != nil {
		return res, err
	}

	log.Debugw("loading SG-SG-ICMP rules...")
	if err = res.SgSgIcmpRules.Load(ctx, client, res.LocalSGs); err != nil {
		return res, err
	}

	log.Debugw("loading SG-SG-INGRESS/EGRESS-ICMP rules...")
	if err = res.SgIeSgIcmpRules.Load(ctx, client, res.LocalSGs); err != nil {
		return res, err
	}

	log.Debugw("loading SG-FQDN rules...")
	if err = res.SG2FQDNRules.Load(ctx, client, res.LocalSGs); err != nil {
		return res, err
	}

	log.Debugw("loading CIDR-SG-INGRESS/EGRESS rules...")
	if err = res.CidrSgRules.Load(ctx, client, res.LocalSGs); err != nil {
		return res, err
	}

	log.Debugw("loading SG-INGRESS/EGRESS-SG rules...")
	if err = res.SgIeSgRules.Load(ctx, client, res.LocalSGs); err != nil {
		return res, err
	}

	log.Debugw("loading INGRESS/EGRESS-ICMP-SG-ICMP rules...")
	if err = res.IECidrSgIcmpRules.Load(ctx, client, res.LocalSGs); err != nil {
		return res, err
	}

	if nonLocalSgs := res.nonLocalSGs(); len(nonLocalSgs) > 0 {
		log.Debugf("loading networks from non local SG(s) %s...", nonLocalSgs)
		err = res.Networks.LoadFromSGNames(ctx, client, nonLocalSgs)
	}

	return res, err
}
