package nft

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/H-BF/sgroups/cmd/to-nft/internal"
	"github.com/H-BF/sgroups/cmd/to-nft/internal/dns"
	"github.com/H-BF/sgroups/cmd/to-nft/internal/nft/cases"
	"github.com/H-BF/sgroups/internal/config"

	"github.com/H-BF/corlib/logger"
	pkgNet "github.com/H-BF/corlib/pkg/net"
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
			r dns.Resolver
		)
		ret.getDnsResolver = func(ctx context.Context) (dns.Resolver, error) {
			o.Do(func() {
				r, e = dns.NewResolver(ctx)
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
			ret.getDnsResolver = func(_ context.Context) (dns.Resolver, error) {
				if t.Resolver == nil {
					return nil, errors.New("has no DNS resolver")
				}
				return t.Resolver, nil
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
		getDnsResolver func(context.Context) (dns.Resolver, error)
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
	log.Debugw("loading SG-SG rules...", "host-local-IP(s)", slice2stringer(allLoaclIPs...))
	if localRules, err = impl.loadLocalRules(ctx, localSGs); err != nil {
		return applied, err
	}
	applied.SG2SGRules = localRules
	log.Debugw("loading SG-FQDN rules...", "local-SG(s)", slice2stringer(localSGs.Names()...))
	if fqdnRules, err = impl.loadFQDNRules(ctx, localRules); err != nil {
		return applied, err
	}
	applied.SG2FQDNRules = fqdnRules
	log.Infof("data loaded; will apply it now")

	pfm := BatchPerformer{
		TableName:  "main",
		LocalRules: localRules,
		Tx: func() (*Tx, error) {
			return NewTx(impl.netNS)
		},
	}
	err = pfm.Exec(ctx,
		WithLogger(log),
		WithBaseRules(impl.baseRules),
		WithSg2FqdnRules(fqdnRules),
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
	const api = "load-local-rules"
	var ret cases.SG2SGRules
	err := ret.Load(ctx, impl.sgClient, localSGs)
	return ret, errors.WithMessage(err, api)
}

func (impl *nfTablesProcessorImpl) loadLocalSG(ctx context.Context, localIPs []net.IP) (cases.SGs, error) {
	const api = "load-local-SG(s)"
	var ret cases.SGs
	err := ret.LoadFromIPs(ctx, impl.sgClient, localIPs)
	return ret, errors.WithMessage(err, api)
}

func (impl *nfTablesProcessorImpl) loadFQDNRules(ctx context.Context, localRules cases.SG2SGRules) (cases.SG2FQDNRules, error) {
	const api = "load-FQDN-rules"
	var ret cases.SG2FQDNRules
	dnsR, err := impl.getDnsResolver(ctx)
	if err != nil {
		return ret, err
	}
	ret, err = cases.FQDNRulesLoader{
		SGSrv:  impl.sgClient,
		DnsRes: dnsR,
	}.Load(ctx, localRules)
	return ret, errors.WithMessage(err, api)
}

// IfBaseRulesFromConfig -
func IfBaseRulesFromConfig(ctx context.Context, cons func(BaseRules) error) error {
	def := internal.BaseRulesOutNets.OptDefaulter(func() ([]config.NetCIDR, error) {
		a, e := internal.SGroupsAddress.Value(ctx)
		if e != nil {
			return nil, e
		}
		var ep *pkgNet.Endpoint
		if ep, e = pkgNet.ParseEndpoint(a); e != nil {
			return nil, e
		}
		if ep.Network() != "tcp" {
			return nil, config.ErrNotFound
		}
		h, _, _ := ep.HostPort()
		ip := net.ParseIP(h)
		if ip == nil {
			return nil, errors.Errorf("'sgroups' server address must be an in 'IP' form; we got(%s)", a)
		}
		ips := ip.String()
		b := bytes.NewBuffer(nil)
		_, _ = fmt.Fprintf(b, `["%s/%s"]`, ips, tern(strings.ContainsAny(ips, ":"), "128", "32"))
		var x []config.NetCIDR
		if e = json.Unmarshal(b.Bytes(), &x); e != nil {
			panic(e)
		}
		return x, nil
	})
	nets, err := internal.BaseRulesOutNets.Value(ctx, def)
	if err != nil {
		if errors.Is(err, config.ErrNotFound) {
			return nil
		}
		return err
	}
	br := BaseRules{
		Nets: nets,
	}
	return cons(br)
}
