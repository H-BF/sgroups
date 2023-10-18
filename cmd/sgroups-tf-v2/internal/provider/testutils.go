package provider

import (
	"context"

	protos "github.com/H-BF/protos/pkg/api/sgroups"
	sgAPI "github.com/H-BF/sgroups/internal/api/sgroups"

	"github.com/H-BF/protos/pkg/api/common"
)

func createTestNetworks(ctx context.Context, client *sgAPI.Client) (func(), error) {
	netsData := map[string]string{
		"nw1": "100.10.10.0/24",
		"nw2": "100.20.10.0/24",
		"nw3": "100.30.10.0/24",
		"nw4": "100.40.10.0/24",
		"nw5": "100.50.10.0/24",
	}
	syncNetworks := protos.SyncNetworks{}
	for name, cidr := range netsData {
		syncNetworks.Networks = append(syncNetworks.Networks, &protos.Network{
			Name:    name,
			Network: &common.Networks_NetIP{CIDR: cidr},
		})
	}
	req := protos.SyncReq{
		SyncOp: protos.SyncReq_Upsert,
		Subject: &protos.SyncReq_Networks{
			Networks: &syncNetworks,
		},
	}
	_, err := client.Sync(ctx, &req)
	deleteNetworks := func() {
		_, _ = client.Sync(ctx, &protos.SyncReq{
			SyncOp: protos.SyncReq_Delete,
			Subject: &protos.SyncReq_Networks{
				Networks: &syncNetworks,
			},
		})
	}
	return deleteNetworks, err
}
