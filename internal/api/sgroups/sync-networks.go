package sgroups

import (
	"context"
	"net"

	model "github.com/H-BF/sgroups/internal/models/sgroups"
	registry "github.com/H-BF/sgroups/internal/registry/sgroups"

	sg "github.com/H-BF/protos/pkg/api/sgroups"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type syncNetworks struct {
	wr       registry.Writer
	networks []*sg.Network
	ops      sg.SyncReq_SyncOp
}

type network struct {
	model.Network
}

func (n *network) from(protoNw *sg.Network) error {
	n.Name = protoNw.GetName()
	c := protoNw.GetNetwork().GetCIDR()
	_, nt, err := net.ParseCIDR(c)
	if err != nil {
		return err
	}
	n.Net = *nt
	return nil
}

func (snc syncNetworks) process(ctx context.Context) error {
	var networks []model.Network
	var names []string
	for _, src := range snc.networks {
		if snc.ops == sg.SyncReq_Delete {
			if names == nil {
				names = make([]string, 0, len(snc.networks))
			}
			names = append(names, src.GetName())
		} else {
			if networks == nil {
				networks = make([]model.Network, 0, len(snc.networks))
			}
			var item network
			if e := item.from(src); e != nil {
				return status.Error(codes.InvalidArgument, e.Error())
			}
			networks = append(networks, item.Network)
		}
	}
	var sc registry.Scope = registry.NoScope
	if snc.ops == sg.SyncReq_Delete {
		sc = registry.NetworkNames(names...)
	}
	var opts []registry.Option
	if err := syncOptionsFromProto(snc.ops, &opts); err != nil {
		return err
	}
	return snc.wr.SyncNetworks(ctx, networks, sc, opts...)
}

func syncOptionsFromProto(o sg.SyncReq_SyncOp, opts *[]registry.Option) error {
	switch o {
	case sg.SyncReq_Upsert:
		*opts = append(*opts, registry.SyncOmitDelete{})
	case sg.SyncReq_Delete:
		*opts = append(*opts, registry.SyncOmitInsert{}, registry.SyncOmitUpdate{})
	case sg.SyncReq_FullSync:
	default:
		return status.Error(codes.InvalidArgument, "unsupported sync option")
	}
	return nil
}
