package nft

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"

	"github.com/H-BF/sgroups/cmd/to-nft/internal"
	"github.com/H-BF/sgroups/cmd/to-nft/internal/nft/cases"
	"github.com/H-BF/sgroups/internal/config"
	pkgErr "github.com/H-BF/sgroups/pkg/errors"

	"github.com/H-BF/corlib/logger"
	pkgNet "github.com/H-BF/corlib/pkg/net"
	sgAPI "github.com/H-BF/protos/pkg/api/sgroups"
	nftLib "github.com/google/nftables"
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
			ret.baseRules = &t
		}
	}
	return ret
}

type (
	// SGClient is a type alias
	SGClient = sgAPI.SecGroupServiceClient

	nfTablesProcessorImpl struct {
		sgClient  SGClient
		netNS     string
		baseRules *BaseRules
	}

	ipVersion = int
)

// ApplyConf impl 'NfTablesProcessor'
func (impl *nfTablesProcessorImpl) ApplyConf(ctx context.Context, conf NetConf) error {
	const api = "ApplyConf"

	var (
		err        error
		localRules cases.LocalRules
		localSGs   cases.SGs
		_          cases.FQDNRules
	)

	localIPsV4, loaclIPsV6 := conf.LocalIPs()
	allLoaclIPs := append(localIPsV4, loaclIPsV6...)
	if err = localSGs.LoadFromIPs(ctx, impl.sgClient, allLoaclIPs); err != nil {
		return multierr.Combine(ErrNfTablesProcessor,
			err, pkgErr.ErrDetails{Api: api, Details: allLoaclIPs})
	}
	if err = localRules.Load(ctx, impl.sgClient, localSGs); err != nil {
		return multierr.Combine(ErrNfTablesProcessor,
			err, pkgErr.ErrDetails{Api: api})
	}

	tblMain := &nftLib.Table{
		Name:   "main",
		Family: nftLib.TableFamilyINet,
	}

	log := logger.FromContext(ctx).Named("nft")
	if len(impl.netNS) > 0 {
		log = log.WithField("NetNS", impl.netNS)
	}
	btch := batch{
		log: log,
		txProvider: func() (*nfTablesTx, error) {
			return nfTx(impl.netNS)
		},
	}
	err = btch.execute(ctx, tblMain, localRules, impl.baseRules)
	if err != nil {
		return multierr.Combine(ErrNfTablesProcessor, err,
			pkgErr.ErrDetails{Api: api})
	}
	return nil
}

// Close impl 'NfTablesProcessor'
func (impl *nfTablesProcessorImpl) Close() error {
	return nil
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
