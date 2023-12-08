package nft

import (
	"context"
	"net"

	"github.com/H-BF/sgroups/cmd/to-nft/internal"
	"github.com/H-BF/sgroups/cmd/to-nft/internal/nft/cases"

	"github.com/H-BF/corlib/logger"
	sgAPI "github.com/H-BF/protos/pkg/api/sgroups"
	"github.com/pkg/errors"
	"go.uber.org/multierr"
)

// NewNfTablesProcessor creates NfTablesProcessor from SGClient
func NewNfTablesProcessor(client SGClient, opts ...NfTablesProcessorOpt) NfTablesProcessor {
	ret := &nfTablesProcessorImpl{
		sgClient: client,
	}
	for _, o := range opts {
		switch t := o.(type) {
		case WithNetNS:
			ret.netNS = t.NetNS
		case BaseRules:
			ret.baseRules = t
		case DnsResolver:
			ret.dnsResolver = t.DomainAddressQuerier
		}
	}
	return ret
}

type (
	// SGClient is a type alias
	SGClient = sgAPI.SecGroupServiceClient

	nfTablesProcessorImpl struct {
		sgClient    SGClient
		netNS       string
		baseRules   BaseRules
		dnsResolver internal.DomainAddressQuerier
	}

	ipVersion = int
)

// ApplyConf impl 'NfTablesProcessor'
func (impl *nfTablesProcessorImpl) ApplyConf(ctx context.Context, netConf NetConf) (applied AppliedRules, err error) {
	const api = "nft/ApplyConf"

	log := logger.FromContext(ctx).Named("nft").Named("ApplyConf")
	if len(impl.netNS) > 0 {
		log = log.WithField("net-ns", impl.netNS)
	}
	log.Info("begin")
	defer func() {
		if err == nil {
			log.Info("succeeded")
		} else {
			log.Error(err)
			err = errors.WithMessage(multierr.Combine(
				ErrNfTablesProcessor, err,
			), api)
		}
	}()

	var (
		localRules cases.SG2SGRules
		fqdnRules  cases.SG2FQDNRules
		networks   cases.SGsNetworks
	)

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

	pfm := BatchPerformer{
		TableName: "main",
		Tx: func() (*Tx, error) {
			return NewTx(impl.netNS)
		},
	}
	err = pfm.Exec(ctx,
		WithLogger(log),
		WithNetworks(networks),
		WithBaseRules(impl.baseRules),
		WithSg2FqdnRules(fqdnRules),
		WithSg2SgRules(localRules),
		WithSgSgIcmpRules(applied.SgSgIcmpRules),
		WithSgIcmpRules(applied.SgIcmpRules),
		WithLocalSGs(applied.LocalSGs),
		WithCidrSgRules(applied.CidrSgRules),
	)
	if err == nil {
		applied.BaseRules = impl.baseRules
		applied.TargetTable = pfm.TableName
		applied.NetNS = impl.netNS
	}
	return applied, err
}

// Close impl 'NfTablesProcessor'
func (impl *nfTablesProcessorImpl) Close() error {
	return nil
}

func (impl *nfTablesProcessorImpl) loadSgSgRules(ctx context.Context, localSGs cases.SGs) (cases.SG2SGRules, error) {
	var ret cases.SG2SGRules
	err := ret.Load(ctx, impl.sgClient, localSGs)
	return ret, err
}

func (impl *nfTablesProcessorImpl) loadLocalSGs(ctx context.Context, localIPs []net.IP) (cases.SGs, error) {
	var ret cases.SGs
	err := ret.LoadFromIPs(ctx, impl.sgClient, localIPs)
	return ret, err
}

func (impl *nfTablesProcessorImpl) loadFQDNRules(ctx context.Context, sgs cases.SGs) (cases.SG2FQDNRules, error) {
	var ret cases.SG2FQDNRules
	ret, err := cases.FQDNRulesLoader{
		SGSrv:  impl.sgClient,
		DnsRes: impl.dnsResolver,
	}.Load(ctx, sgs)
	return ret, err
}
