package provider

import (
	"context"
	"time"

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
