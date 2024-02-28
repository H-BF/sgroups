package cases

import (
	"context"
	"net"
	"time"

	"github.com/H-BF/sgroups/cmd/to-nft/internal/host"
	"github.com/H-BF/sgroups/internal/dict"
	model "github.com/H-BF/sgroups/internal/models/sgroups"

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
		Networks      SGsNetworks

		ResolvedFQDN *ResolvedFQDN
		SyncStatus   model.SyncStatus
	}

	// LocalDataLoader
	LocalDataLoader struct {
		SyncStatus      model.SyncStatus
		MaxLoadDiration time.Duration
	}
)

// IsEq checks wether this object is equal the other one
func (ld *LocalData) IsEq(other LocalData) bool {
	eq := ld.LocalSGs.IsEq(other.LocalSGs)
	if eq {
		eq = ld.SG2SGRules.IsEq(other.SG2SGRules)
	}
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
		eq = ld.Networks.IsEq(other.Networks)
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
	if err = res.SG2FQDNRules.Load(ctx, client, res.LocalSGs); err != nil {
		return res, err
	}

	log.Debugw("loading CIDR-SG-INGRESS/EGRESS rules...")
	if err = res.CidrSgRules.Load(ctx, client, res.LocalSGs); err != nil {
		return res, err
	}

	var allSgNames []string
	{
		var set dict.HSet[string]
		set.PutMany(res.LocalSGs.Keys()...)
		set.PutMany(res.SG2SGRules.SGs.Keys()...)
		set.PutMany(res.SG2FQDNRules.SGs.Keys()...)
		set.PutMany(res.SgIcmpRules.SGs.Keys()...)
		set.PutMany(res.SgSgIcmpRules.SGs.Keys()...)
		set.PutMany(res.CidrSgRules.SGs.Keys()...)
		allSgNames = set.Values()
	}
	log.Debugw("loading networks...")
	err = res.Networks.LoadFromSGNames(ctx, client, allSgNames)

	return res, err
}
