package nft

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"

	"github.com/H-BF/sgroups/cmd/to-nft/internal"

	pkgNet "github.com/H-BF/corlib/pkg/net"
	config "github.com/H-BF/corlib/pkg/plain-config"
	"github.com/pkg/errors"
)

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
