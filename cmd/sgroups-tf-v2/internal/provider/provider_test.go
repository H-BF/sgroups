package provider

import (
	"context"
	"time"

	sgAPI "github.com/H-BF/sgroups/internal/api/sgroups"
	client "github.com/H-BF/sgroups/internal/grpc-client"

	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
)

var (
	testAccProviders map[string]func() (tfprotov6.ProviderServer, error)
	testAccProvider  provider.Provider
	testAccSgClient  sgAPI.Client
)

func init() {
	address := lookupEnvWithDefault("SGROUPS_ADDRESS", "tcp://127.0.0.1:9000")
	dialDuration := lookupEnvWithDefault("SGROUPS_DIAL_DURATION", "10s")
	connDuration, _ := time.ParseDuration(dialDuration)
	c, err := client.FromAddress(address).
		WithDialDuration(connDuration).
		New(context.Background())
	if err != nil {
		panic(err.Error())
	}

	testAccSgClient = sgAPI.NewClient(c)
	testAccProvider = Factory("test")()
	testAccProviders = map[string]func() (tfprotov6.ProviderServer, error){
		"sgroups": providerserver.NewProtocol6WithError(testAccProvider),
	}
}
