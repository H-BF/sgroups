package cases

import (
	"context"
	"net"

	"github.com/H-BF/sgroups/cmd/to-nft/internal"
	"github.com/H-BF/sgroups/cmd/to-nft/internal/host"

	"github.com/H-BF/corlib/logger"
	"github.com/pkg/errors"
)

// LocalData are used by agent to build Host Based Firewall rules
type LocalData struct {
	LocalSGs      SGs
	SG2SGRules    SG2SGRules
	SG2FQDNRules  SG2FQDNRules
	SgIcmpRules   SgIcmpRules
	SgSgIcmpRules SgSgIcmpRules
	CidrSgRules   CidrSgRules
	Networks      SGsNetworks
}

// LocalDataLoader
type LocalDataLoader struct {
	Logger logger.TypeOfLogger
	DnsRes internal.DomainAddressQuerier // optional
}

// IsEq checks wether this object is equal the other one
func (ld *LocalData) IsEq(other LocalData) bool {
	return ld.LocalSGs.IsEq(other.LocalSGs) &&
		ld.SG2SGRules.IsEq(other.SG2SGRules) &&
		ld.SG2FQDNRules.IsEq(other.SG2FQDNRules) &&
		ld.SgIcmpRules.IsEq(other.SgIcmpRules) &&
		ld.SgSgIcmpRules.IsEq(other.SgSgIcmpRules) &&
		ld.CidrSgRules.IsEq(other.CidrSgRules) &&
		ld.Networks.IsEq(other.Networks)
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
	_ = locIPs

	return res, err
}

/*//
localIPsV4, loaclIPsV6 := netConf.LocalIPs()
allLoaclIPs := append(localIPsV4, loaclIPsV6...)
log.Infof("start loading data according host net config")

log.Debugw("loading SG...", "host-local-IP(s)", slice2stringer(allLoaclIPs...))
if applied.LocalSGs, err = impl.loadLocalSGs(ctx, allLoaclIPs); err != nil {
	return applied, err
}

stringerOfLocalSGs := slice2stringer(applied.LocalSGs.Names()...)
log.Debugw("loading SG-SG rules...", "local-SG(s)", stringerOfLocalSGs)
if localRules, err = impl.loadSgSgRules(ctx, applied.LocalSGs); err != nil {
	return applied, err
}
applied.SG2SGRules = localRules

log.Debugw("loading SG-ICMP rules...", "local-SG(s)", stringerOfLocalSGs)
if err = applied.SgIcmpRules.Load(ctx, impl.sgClient, applied.LocalSGs); err != nil {
	return applied, err
}

log.Debugw("loading SG-SG-ICMP rules...", "local-SG(s)", stringerOfLocalSGs)
if err = applied.SgSgIcmpRules.Load(ctx, impl.sgClient, applied.LocalSGs); err != nil {
	return applied, err
}

log.Debugw("loading SG-FQDN rules...", "local-SG(s)", stringerOfLocalSGs)
if fqdnRules, err = impl.loadFQDNRules(ctx, applied.LocalSGs); err != nil {
	return applied, err
}
applied.SG2FQDNRules = fqdnRules

log.Debugw("loading CIDR-SG-INGRESS/EGRESS rules...", "local-SG(s)", stringerOfLocalSGs)
if err = applied.CidrSgRules.Load(ctx, impl.sgClient, applied.LocalSGs); err != nil {
	return applied, err
}

sgNames := applied.GetAllUsedSgNames()
log.Debugw("loading networks...", "SG(s)", slice2stringer(sgNames...))
if err = networks.LoadFromSGNames(ctx, impl.sgClient, sgNames); err != nil {
	return applied, err
}
log.Info("data loaded; will apply it now")
*/

/*//
func stringers(args ...fmt.Stringer) []fmt.Stringer {
	return args
}
*/
