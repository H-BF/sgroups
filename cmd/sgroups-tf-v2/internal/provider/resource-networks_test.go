package provider

import (
	"context"
	"strings"
	"testing"

	protos "github.com/H-BF/protos/pkg/api/sgroups"
	"github.com/H-BF/sgroups/cmd/sgroups-tf-v2/internal/provider/fixtures"
	"github.com/stretchr/testify/suite"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

type networksTests struct {
	baseResourceTests
}

func TestAccNetworks(t *testing.T) {
	suite.Run(t, new(networksTests))
}

func (sui *networksTests) TestNetworks() {
	var creationFixture, modificationFixture fixtures.NetworksRC

	sui.Require().NoError(creationFixture.LoadFixture("networks/c.yml"))
	sui.Require().NoError(modificationFixture.LoadFixture("networks/m.yml"))

	for _, net := range creationFixture.Spec {
		sui.Require().Nilf(sui.getNetwork(net.Name), "there are network %s already", net.Name)
	}

	resource.Test(sui.T(), resource.TestCase{
		ProtoV6ProviderFactories: sui.providerFactories,
		Steps: []resource.TestStep{
			{
				Config: sui.fixtureTfConfig(creationFixture),
				Check: func(_ *terraform.State) error {
					for _, netData := range creationFixture.Spec {
						net := sui.getNetwork(netData.Name)
						sui.Require().NotNilf(net, "network %s not found", netData.Name)
						sui.Require().Equal(net.GetNetwork().CIDR, netData.Cidr)
					}
					return nil
				},
			},
			{
				Config: sui.fixtureTfConfig(modificationFixture),
				Check: func(_ *terraform.State) error {
					for _, netData := range modificationFixture.Spec {
						net := sui.getNetwork(netData.Name)
						sui.Require().NotNilf(net, "network %s not found", netData.Name)
						sui.Require().Equal(net.GetNetwork().CIDR, netData.Cidr)
					}

					for name, netData := range creationFixture.Spec {
						if _, contains := modificationFixture.Spec[name]; !contains {
							net := sui.getNetwork(netData.Name)
							sui.Require().Nilf(net, "network %s should be deleted", netData.Name)
						}
					}

					return nil
				},
			},
		},
	})
}

func (sui *networksTests) getNetwork(netName string) *protos.Network {
	resp, err := sui.sgClient.ListNetworks(context.Background(), &protos.ListNetworksReq{
		NeteworkNames: []string{netName},
	})
	sui.Require().NoError(err)

	if len(resp.GetNetworks()) == 0 {
		return nil
	}

	return resp.GetNetworks()[0]
}

func (sui *networksTests) fixtureTfConfig(f fixtures.NetworksRC) string {
	config := new(strings.Builder)
	sui.Require().NoError(f.TfRcConf(config))
	return config.String()
}
