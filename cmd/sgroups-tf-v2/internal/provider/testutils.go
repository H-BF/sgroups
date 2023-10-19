package provider

import (
	"context"

	"github.com/H-BF/protos/pkg/api/common"
	protos "github.com/H-BF/protos/pkg/api/sgroups"
	sgAPI "github.com/H-BF/sgroups/internal/api/sgroups"
	model "github.com/H-BF/sgroups/internal/models/sgroups"

	"github.com/hashicorp/terraform-plugin-framework/types"
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

func createTestSecGroups(ctx context.Context, client *sgAPI.Client) (func(), error) {
	sgsData := []sgTestData{
		{
			name:          "sg1",
			defaultAction: "ACCEPT",
			network_names: []string{"nw1"},
		},
		{
			name:          "sg2",
			logs:          true,
			trace:         true,
			defaultAction: "DROP",
			network_names: []string{"nw2"},
		},
		{
			name:          "sg3",
			defaultAction: "ACCEPT",
			network_names: []string{"nw3", "nw5"},
		},
		{
			name:          "sg4",
			logs:          true,
			trace:         true,
			defaultAction: "DROP",
			network_names: []string{"nw4"},
		},
	}

	deleteNetworks, err := createTestNetworks(ctx, client)
	if err != nil {
		return nil, err
	}

	syncSg := protos.SyncSecurityGroups{}
	for _, sgData := range sgsData {
		da := protos.SecGroup_DefaultAction_value[sgData.defaultAction]
		syncSg.Groups = append(syncSg.Groups, &protos.SecGroup{
			Name:          sgData.name,
			Networks:      sgData.network_names,
			DefaultAction: protos.SecGroup_DefaultAction(da),
			Trace:         sgData.trace,
			Logs:          sgData.logs,
		})
	}

	req := protos.SyncReq{
		SyncOp: protos.SyncReq_Upsert,
		Subject: &protos.SyncReq_Groups{
			Groups: &syncSg,
		},
	}
	_, err = client.Sync(ctx, &req)
	deleteNetworksAndSgs := func() {
		_, _ = client.Sync(ctx, &protos.SyncReq{
			SyncOp: protos.SyncReq_Delete,
			Subject: &protos.SyncReq_Groups{
				Groups: &syncSg,
			},
		})
		deleteNetworks()
	}

	return deleteNetworksAndSgs, err
}

func areRulePortsEq(rulePorts []*protos.AccPorts, testDataPorts []accPorts) (bool, error) {
	var rPorts, tdPorts []AccessPorts
	for _, p := range rulePorts {
		rPorts = append(rPorts, AccessPorts{
			Source:      types.StringValue(p.S),
			Destination: types.StringValue(p.D),
		})
	}

	for _, p := range testDataPorts {
		tdPorts = append(tdPorts, AccessPorts{
			Source:      types.StringValue(p.s),
			Destination: types.StringValue(p.d),
		})
	}

	rModelPorts, err := toModelPorts(rPorts)
	if err != nil {
		return false, err
	}

	tdModelPorts, err := toModelPorts(tdPorts)
	if err != nil {
		return false, err
	}

	return model.AreRulePortsEq(rModelPorts, tdModelPorts), nil
}
