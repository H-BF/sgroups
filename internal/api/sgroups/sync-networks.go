package sgroups

import (
	"context"
	"net"

	sg "github.com/H-BF/protos/pkg/api/sgroups"
	model "github.com/H-BF/sgroups/internal/models/sgroups"
	registry "github.com/H-BF/sgroups/internal/registry/sgroups"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type syncNetworks struct {
	srv      *sgService
	networks []*sg.Network
	ops      sg.SyncReq_SyncOp
}

type network struct {
	model.Network
}

func (n *network) from(protoNw *sg.Network) error {
	n.Name = protoNw.GetName()
	_, nt, err := net.ParseCIDR(protoNw.GetNetwork().GetCIDR())
	if err != nil {
		return err
	}
	n.Net = *nt
	return nil
}

func (snc syncNetworks) process(ctx context.Context) error {
	dst := make([]model.Network, 0, len(snc.networks))
	names := make([]string, 0, len(snc.networks))
	for _, src := range snc.networks {
		var item network
		if e := item.from(src); e != nil {
			return status.Errorf(codes.InvalidArgument, "when convert (%s) network", src)
		}
		if snc.ops != sg.SyncReq_FullSync {
			names = append(names, src.GetName())
		}
		dst = append(dst, item.Network)
	}
	var sc registry.Scope = registry.NoScope
	if len(names) != 0 {
		sc = registry.NetworkNames(names[0], names[1:]...)
	}
	var opts []registry.Option
	if err := syncOptionsFromProto(snc.ops, &opts); err != nil {
		return err
	}
	writer := snc.srv.registryWriter()
	return writer.SyncNetworks(ctx, dst, sc, opts...)
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
