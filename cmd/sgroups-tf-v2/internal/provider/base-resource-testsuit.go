package provider

import (
	"bytes"
	"context"
	"fmt"
	"strings"
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
	ctxCancel         func()
	sgClient          sgAPI.ClosableClient
	providerFactories map[string]func() (tfprotov6.ProviderServer, error)
	cleanDB           func()
}

func (sui *baseResourceTests) SetupSuite() {
	sui.ctx = context.Background()
	if dl, ok := sui.T().Deadline(); ok {
		sui.ctx, sui.ctxCancel = context.WithDeadline(sui.ctx, dl)
	}

	address := lookupEnvWithDefault("SGROUPS_ADDRESS", "tcp://127.0.0.1:9000")
	dialDuration := lookupEnvWithDefault("SGROUPS_DIAL_DURATION", "10s")
	connDuration, err := time.ParseDuration(dialDuration)
	sui.Require().Nil(err)

	builder := client.FromAddress(address).
		WithDialDuration(connDuration)

	sui.sgClient, err = sgAPI.NewClosableClient(sui.ctx, builder)
	sui.Require().NoError(err)

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
	if sui.ctxCancel != nil {
		sui.ctxCancel()
	}
}

func slice2string[T fmt.Stringer](args ...T) string {
	data := bytes.NewBuffer(nil)
	for i, o := range args {
		if i > 0 {
			_, _ = data.WriteString(";  ")
		}
		_, _ = fmt.Fprintf(data, "%s", o)
	}
	return strings.ReplaceAll(data.String(), `"`, "'")
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
