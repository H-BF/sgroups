package cases

import (
	"context"
	"net"
	"sort"
	"sync"

	sgAPI "github.com/H-BF/protos/pkg/api/sgroups"
	conv "github.com/H-BF/sgroups/internal/api/sgroups"
	model "github.com/H-BF/sgroups/internal/models/sgroups"

	"github.com/H-BF/corlib/pkg/parallel"
	"github.com/H-BF/corlib/pkg/slice"
	"github.com/c-robinson/iplib"
	"github.com/pkg/errors"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type (
	// Network is type alias
	Network = model.Network

	//SgName is a type alias
	SgName = string

	//SGClient is a type alias
	SGClient = sgAPI.SecGroupServiceClient

	// LocalSG ...
	LocalSG struct {
		SG           model.SecurityGroup
		IPsV4, IPsV6 iplib.ByIP
	}

	// LocalSGs local SG(s) related to IP(s)
	LocalSGs map[SgName]*LocalSG
)

// Load it loads Local SGs by IPs
func (loc *LocalSGs) Load(ctx context.Context, client SGClient, srcIPs []net.IP) error {
	const api = "LocalSG(s)/Load"

	*loc = make(LocalSGs)
	if len(srcIPs) == 0 {
		return nil
	}
	var mx sync.Mutex
	job := func(i int) error {
		srcIP := srcIPs[i]
		req := &sgAPI.GetSecGroupForAddressReq{
			Address: srcIP.String(),
		}
		resp, err := client.GetSecGroupForAddress(ctx, req)
		if err != nil {
			if status.Code(errors.Cause(err)) == codes.NotFound {
				return nil
			}
			return err
		}
		var sg model.SecurityGroup
		if sg, err = conv.Proto2ModelSG(resp); err != nil {
			return err
		}
		mx.Lock()
		defer mx.Unlock()
		it := (*loc)[sg.Name]
		if it == nil {
			it = &LocalSG{SG: sg}
			(*loc)[sg.Name] = it
		}
		switch len(srcIP) {
		case net.IPv4len:
			it.IPsV4 = append(it.IPsV4, srcIP)
		case net.IPv6len:
			it.IPsV6 = append(it.IPsV6, srcIP)
		}
		return nil
	}
	if err := parallel.ExecAbstract(len(srcIPs), 8, job); err != nil { //nolint:gomnd
		return errors.WithMessage(err, api)
	}
	for _, it := range *loc {
		lst := []*iplib.ByIP{&it.IPsV4, &it.IPsV6}
		for _, ips := range lst {
			sort.Sort(*ips)
			_ = slice.DedupSlice(ips, func(i, j int) bool {
				l, r := (*ips)[i], (*ips)[j]
				return l.Equal(r)
			})
		}
	}
	return nil
}

// Names get local SG(s) names
func (loc LocalSGs) Names() []SgName {
	ret := make([]SgName, 0, len(loc))
	for n := range loc {
		ret = append(ret, n)
	}
	return ret
}
