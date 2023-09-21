package nft

import (
	"context"
	"net"
	"sync"

	"github.com/H-BF/sgroups/cmd/to-nft/internal/dns"
	"github.com/H-BF/sgroups/cmd/to-nft/internal/nft/cases"
	"github.com/ahmetb/go-linq/v3"

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

	{
		var (
			o sync.Once
			e error
			r dns.DomainAddressQuerier
		)
		ret.getDnsResolver = func(ctx context.Context) (dns.DomainAddressQuerier, error) {
			o.Do(func() {
				r, e = dns.NewDomainAddressQuerier(ctx)
			})
			return r, e
		}
	}
	for _, o := range opts {
		switch t := o.(type) {
		case WithNetNS:
			ret.netNS = t.NetNS
		case BaseRules:
			ret.baseRules = t
		case DnsResolver:
			ret.getDnsResolver = func(_ context.Context) (dns.DomainAddressQuerier, error) {
				if t.DomainAddressQuerier == nil {
					return nil, errors.New("has no DNS resolver")
				}
				return t.DomainAddressQuerier, nil
			}
		}
	}
	return ret
}

type (
	// SGClient is a type alias
	SGClient = sgAPI.SecGroupServiceClient

	nfTablesProcessorImpl struct {
		sgClient       SGClient
		netNS          string
		baseRules      BaseRules
		getDnsResolver func(context.Context) (dns.DomainAddressQuerier, error)
	}

	ipVersion = int
)

// ApplyConf impl 'NfTablesProcessor'
func (impl *nfTablesProcessorImpl) ApplyConf(ctx context.Context, conf NetConf) (applied AppliedRules, err error) {
	const api = "nft/ApplyConf"

	defer func() {
		if err != nil {
			err = errors.WithMessage(multierr.Combine(
				ErrNfTablesProcessor, err,
			), api)
		}
	}()

	var (
		localRules cases.SG2SGRules
		localSGs   cases.SGs
		fqdnRules  cases.SG2FQDNRules
		networks   cases.SGsNetworks
	)
	log := logger.FromContext(ctx).Named("nft")
	if len(impl.netNS) > 0 {
		log = log.WithField("net-NS", impl.netNS)
	}

	localIPsV4, loaclIPsV6 := conf.LocalIPs()
	allLoaclIPs := append(localIPsV4, loaclIPsV6...)

	log.Infof("start loading data acording host net config")
	log.Debugw("loading SG...", "host-local-IP(s)", slice2stringer(allLoaclIPs...))
	if localSGs, err = impl.loadLocalSG(ctx, allLoaclIPs); err != nil {
		return applied, err
	}

	stringerOfLocalSGs := slice2stringer(localSGs.Names()...)
	log.Debugw("loading SG-SG rules...", "local-SG(s)", stringerOfLocalSGs)
	if localRules, err = impl.loadLocalRules(ctx, localSGs); err != nil {
		return applied, err
	}
	applied.SG2SGRules = localRules

	log.Debugw("loading SG-FQDN rules...", "local-SG(s)", stringerOfLocalSGs)
	if fqdnRules, err = impl.loadFQDNRules(ctx, localSGs); err != nil {
		return applied, err
	}
	applied.SG2FQDNRules = fqdnRules

	var sgNames []string
	linq.From(append(localRules.SGs.Names(), fqdnRules.SGs.Names()...)).
		Distinct().ToSlice(&sgNames)
	log.Debugw("loading networks...", "SG(s)", slice2stringer(sgNames...))
	if err = networks.LoadFromSGNames(ctx, impl.sgClient, sgNames); err != nil {
		return applied, err
	}

	log.Infof("data loaded; will apply it now")
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
	)
	if err == nil {
		applied.SavedNftConf, err = impl.loadNftConfig()
		if err == nil {
			log.Debugw("final NFT config done")
			applied.BaseRules = impl.baseRules
			applied.TargetTable = pfm.TableName
		}
	}
	return applied, err
}

func (impl *nfTablesProcessorImpl) loadNftConfig() (cnf NFTablesConf, err error) {
	var tx *Tx
	if tx, err = NewTx(impl.netNS); err != nil {
		return cnf, err
	}
	defer tx.Close()
	err = cnf.Load(tx.Conn)
	return cnf, err
}

// Close impl 'NfTablesProcessor'
func (impl *nfTablesProcessorImpl) Close() error {
	return nil
}

func (impl *nfTablesProcessorImpl) loadLocalRules(ctx context.Context, localSGs cases.SGs) (cases.SG2SGRules, error) {
	var ret cases.SG2SGRules
	err := ret.Load(ctx, impl.sgClient, localSGs)
	return ret, err
}

func (impl *nfTablesProcessorImpl) loadLocalSG(ctx context.Context, localIPs []net.IP) (cases.SGs, error) {
	var ret cases.SGs
	err := ret.LoadFromIPs(ctx, impl.sgClient, localIPs)
	return ret, err
}

func (impl *nfTablesProcessorImpl) loadFQDNRules(ctx context.Context, sgs cases.SGs) (cases.SG2FQDNRules, error) {
	var ret cases.SG2FQDNRules
	dnsR, err := impl.getDnsResolver(ctx)
	if err != nil {
		return ret, errors.WithMessage(err, "DNS resolver is unavailable")
	}
	ret, err = cases.FQDNRulesLoader{
		SGSrv:  impl.sgClient,
		DnsRes: dnsR,
	}.Load(ctx, sgs)
	return ret, err
}
