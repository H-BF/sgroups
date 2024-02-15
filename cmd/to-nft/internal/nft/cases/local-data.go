package cases

import (
	"context"
	"net"

	"github.com/H-BF/sgroups/cmd/to-nft/internal"
	"github.com/H-BF/sgroups/cmd/to-nft/internal/host"

	"github.com/H-BF/corlib/logger"
	"github.com/pkg/errors"
)

type (
	// LocalData are used by agent to build Host Based Firewall rules
	LocalData struct {
		LocalSGs      SGs
		SG2SGRules    SG2SGRules
		SG2FQDNRules  SG2FQDNRules
		SgIcmpRules   SgIcmpRules
		SgSgIcmpRules SgSgIcmpRules
		CidrSgRules   CidrSgRules
		SgIeSgRules   SgIeSgRules
		Networks      SGsNetworks
	}

	// LocalDataLoader
	LocalDataLoader struct {
		Logger logger.TypeOfLogger
		DnsRes internal.DomainAddressQuerier // optional
	}
)

// AllSGs -
func (ld *LocalData) AllSGs() (ret SGs) {
	src := [...]SGs{
		ld.LocalSGs, ld.SG2SGRules.SGs, ld.SgIcmpRules.SGs,
		ld.SgIcmpRules.SGs, ld.SgSgIcmpRules.SGs, ld.SgIeSgRules.SGs,
	}
	for _, s := range src {
		s.Iterate(func(k SgName, v *SG) bool {
			ret.Put(k, v)
			return true
		})
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
		eq = ld.CidrSgRules.IsEq(other.CidrSgRules)
	}
	if eq {
		eq = ld.SgIeSgRules.IsEq(other.SgIeSgRules)
	}
	if eq {
		eq = ld.Networks.IsEq(other.Networks)
	}
	return eq
}

// Load -
func (loader LocalDataLoader) Load(ctx context.Context, client SGClient, ncnf host.NetConf) (res LocalData, err error) {
	defer func() {
		err = errors.WithMessage(err, "LocalData/Load")
	}()

	var locIPs []net.IP
	{
		v4, v6 := ncnf.LocalIPs()
		locIPs = append(append(locIPs, v4...), v6...)
	}
	if len(locIPs) == 0 {
		return res, err
	}

	log := loader.Logger
	log.Debugf("loading local SG(s) from host local IP(s) %s ...", locIPs)
	if err = res.LocalSGs.LoadFromIPs(ctx, client, locIPs); err != nil {
		return res, err
	}
	log.Debugf("found local SG(s) %s", res.LocalSGs.Names())

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

	log.Debugw("loading SG-FQDN rules...")
	res.SG2FQDNRules, err = FQDNRulesLoader{SGSrv: client, DnsRes: loader.DnsRes}.Load(ctx, res.LocalSGs)
	if err != nil {
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

	allSgNames := res.AllSGs().Names()
	log.Debugw("loading networks...")
	err = res.Networks.LoadFromSGNames(ctx, client, allSgNames)

	return res, err
}
