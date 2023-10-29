package provider

import (
	"context"
	"time"

	"github.com/H-BF/protos/pkg/api/common"
	protos "github.com/H-BF/protos/pkg/api/sgroups"
	sgAPI "github.com/H-BF/sgroups/internal/api/sgroups"
	client "github.com/H-BF/sgroups/internal/grpc-client"
	domain "github.com/H-BF/sgroups/internal/models/sgroups"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/stretchr/testify/suite"
)

type baseResourceTests struct {
	suite.Suite

	ctx               context.Context
	sgClient          sgAPI.ClosableClient
	providerFactories map[string]func() (tfprotov6.ProviderServer, error)
	cleanDB           func()
}

func (sui *baseResourceTests) SetupSuite() {
	sui.ctx = context.Background()

	address := lookupEnvWithDefault("SGROUPS_ADDRESS", "tcp://127.0.0.1:9000")
	dialDuration := lookupEnvWithDefault("SGROUPS_DIAL_DURATION", "10s")
	connDuration, err := time.ParseDuration(dialDuration)
	sui.Require().Nil(err)

	builder := client.FromAddress(address).
		WithDialDuration(connDuration)

	sui.sgClient, err = sgAPI.NewClosableClient(sui.ctx, builder)
	sui.Require().Nil(err)

	sui.providerFactories = map[string]func() (tfprotov6.ProviderServer, error){
		"sgroups": providerserver.NewProtocol6WithError(Factory("test")()),
	}
}

func (sui *baseResourceTests) TearDownSuite() {
	if sui.cleanDB != nil {
		sui.cleanDB()
	}
	err := sui.sgClient.CloseConn()
	sui.Require().NoError(err)
}

func (sui *baseResourceTests) createTestNetworks() {
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
	_, err := sui.sgClient.Sync(sui.ctx, &req)
	sui.Require().NoError(err)
	sui.cleanDB = func() {
		_, err = sui.sgClient.Sync(sui.ctx, &protos.SyncReq{
			SyncOp: protos.SyncReq_Delete,
			Subject: &protos.SyncReq_Networks{
				Networks: &syncNetworks,
			},
		})
		sui.Require().NoError(err)
	}
}

func (sui *baseResourceTests) createTestSecGroups() {
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

	sui.createTestNetworks()

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
	_, err := sui.sgClient.Sync(sui.ctx, &req)
	sui.Require().NoError(err)

	deleteNetworks := sui.cleanDB
	sui.cleanDB = func() {
		_, err := sui.sgClient.Sync(sui.ctx, &protos.SyncReq{
			SyncOp: protos.SyncReq_Delete,
			Subject: &protos.SyncReq_Groups{
				Groups: &syncSg,
			},
		})
		sui.Require().NoError(err)
		deleteNetworks()
	}
}

func (sui *baseResourceTests) toDomainPorts(rulePorts []*protos.AccPorts) []domain.SGRulePorts {
	var rPorts []AccessPorts
	for _, p := range rulePorts {
		rPorts = append(rPorts, AccessPorts{
			Source:      types.StringValue(p.S),
			Destination: types.StringValue(p.D),
		})
	}

	rModelPorts, err := toModelPorts(rPorts)
	sui.Require().NoError(err)

	return rModelPorts
}
