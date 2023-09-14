package cases

import (
	"context"
	"net"
	"sort"
	"sync"

	sgAPI "github.com/H-BF/protos/pkg/api/sgroups"
	conv "github.com/H-BF/sgroups/internal/api/sgroups"
	"github.com/H-BF/sgroups/internal/dict"
	model "github.com/H-BF/sgroups/internal/models/sgroups"

	"github.com/H-BF/corlib/pkg/parallel"
	"github.com/H-BF/corlib/pkg/slice"
	"github.com/ahmetb/go-linq/v3"
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

	// SG ...
	SG struct {
		model.SecurityGroup
		IPsV4, IPsV6 iplib.ByIP
	}

	// SGs local SG(s) related to IP(s)
	SGs struct {
		dict.HDict[SgName, *SG]
	}
)

// LoadFromIPs it loads Local SGs by IPs
func (loc *SGs) LoadFromIPs(ctx context.Context, client SGClient, localIPs []net.IP) error {
	const api = "SG(s)/LoadFromIPs"
	loc.Clear()
	if len(localIPs) == 0 {
		return nil
	}
	var mx sync.Mutex
	job := func(i int) error {
		srcIP := localIPs[i]
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
		it := loc.At(sg.Name)
		if it == nil {
			it = &SG{SecurityGroup: sg}
			loc.Put(sg.Name, it)
		}
		switch len(srcIP) {
		case net.IPv4len:
			it.IPsV4 = append(it.IPsV4, srcIP)
		case net.IPv6len:
			it.IPsV6 = append(it.IPsV6, srcIP)
		}
		return nil
	}
	if err := parallel.ExecAbstract(len(localIPs), 8, job); err != nil { //nolint:gomnd
		return errors.WithMessage(err, api)
	}
	loc.Iterate(func(_ string, it *SG) bool {
		for _, ips := range []*iplib.ByIP{&it.IPsV4, &it.IPsV6} {
			sort.Sort(*ips)
			_ = slice.DedupSlice(ips, func(i, j int) bool {
				l, r := (*ips)[i], (*ips)[j]
				return l.Equal(r)
			})
		}
		return true
	})
	return nil
}

// LoadFromRules it loads Local SGs from SG rules
func (loc *SGs) LoadFromRules(ctx context.Context, client SGClient, rules []model.SGRule) error {
	const api = "SG(s)/LoadFromRules"

	loc.Clear()
	usedSG := make([]string, 0, len(rules)*2)
	linq.From(rules).
		SelectMany(func(i any) linq.Query {
			r := i.(model.SGRule)
			return linq.From([...]string{r.ID.SgFrom, r.ID.SgTo})
		}).Distinct().ToSlice(&usedSG)

	if len(usedSG) == 0 {
		return nil
	}
	sgsResp, err := client.ListSecurityGroups(ctx, &sgAPI.ListSecurityGroupsReq{SgNames: usedSG})
	if err != nil {
		return errors.WithMessage(err, api)
	}
	linq.From(sgsResp.GetGroups()).
		ForEach(func(i any) {
			if err != nil {
				return
			}
			g := i.(*sgAPI.SecGroup)
			if sg, e := conv.Proto2ModelSG(g); e != nil {
				err = e
			} else {
				loc.Put(sg.Name, &SG{SecurityGroup: sg})
			}
		})
	return errors.WithMessage(err, api)
}

// Names get local SG(s) names
func (loc SGs) Names() []SgName {
	return loc.Keys()
}
