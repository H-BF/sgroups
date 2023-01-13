package cases

import (
	"context"
	"net"
	"sort"
	"strings"
	"sync"

	"github.com/H-BF/corlib/pkg/parallel"
	"github.com/H-BF/corlib/pkg/slice"
	sgAPI "github.com/H-BF/protos/pkg/api/sgroups"
	conv "github.com/H-BF/sgroups/internal/api/sgroups"
	model "github.com/H-BF/sgroups/internal/models/sgroups"
	"github.com/c-robinson/iplib"
	"github.com/pkg/errors"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type (
	//SgName is a type alias
	SgName = string

	//SG is a type alias
	SG = model.SecurityGroup

	//IPsBySG IPs by SG aggreagate list
	IPsBySG []*itemIPsBySG

	//SGClient is a type alias
	SGClient = sgAPI.SecGroupServiceClient

	itemIPsBySG = struct {
		SG
		IPs iplib.ByIP
	}
)

// Load it loads IPs by SG aggregate
func (obj *IPsBySG) Load(ctx context.Context, client SGClient, ips []net.IP) error {
	const api = "IPsBySG/Load"

	if len(ips) == 0 {
		return nil
	}
	type item = struct {
		SG
		IPs iplib.ByIP
	}
	agg := make(map[SgName]*item)
	var mx sync.Mutex
	job := func(i int) error {
		req := &sgAPI.GetSecGroupForAddressReq{
			Address: ips[i].String(),
		}
		resp, err := client.GetSecGroupForAddress(ctx, req)
		if status.Code(err) == codes.NotFound {
			return nil
		}
		if err != nil {
			return err
		}
		var sg SG
		if sg, err = conv.Proto2ModelSG(resp); err != nil {
			return err
		}
		mx.Lock()
		defer mx.Unlock()
		it := agg[sg.Name]
		if it == nil {
			it = new(item)
			agg[sg.Name] = it
		}
		it.IPs = append(it.IPs, ips[i])
		return nil
	}
	if err := parallel.ExecAbstract(len(ips), 7, job); err != nil {
		return errors.WithMessage(err, api)
	}
	for _, it := range agg {
		*obj = append(*obj, it)
	}
	return nil
}

// Dedup it deduplicates list an its IPs
func (obj *IPsBySG) Dedup() {
	for _, it := range *obj {
		sort.Sort(it.IPs)
		_ = slice.DedupSlice(&it.IPs, func(i, j int) bool {
			return iplib.CompareIPs(it.IPs[i], it.IPs[j]) == 0
		})
	}
	sort.Slice(*obj, func(i, j int) bool {
		return strings.Compare((*obj)[i].SG.Name, (*obj)[j].SG.Name) < 0
	})
	_ = slice.DedupSlice(obj, func(i, j int) bool {
		return strings.EqualFold((*obj)[i].Name, (*obj)[j].Name)
	})
}

// V4andV6 ...
func (obj IPsBySG) V4andV6() (v4 IPsBySG, v6 IPsBySG) {
	for _, src := range obj {
		it4 := itemIPsBySG{SG: src.SG}
		it6 := it4
		for _, ip := range src.IPs {
			switch len(ip) {
			case net.IPv4len:
				it4.IPs = append(it4.IPs, ip)
			case net.IPv6len:
				it6.IPs = append(it6.IPs, ip)
			}
		}
		if len(it4.IPs) > 0 {
			v4 = append(v4, &it4)
		}
		if len(it6.IPs) > 0 {
			v6 = append(v6, &it6)
		}
	}
	return v4, v6
}
