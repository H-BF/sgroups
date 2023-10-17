package provider

import (
	"context"
	"fmt"
	"strings"
	"testing"

	protos "github.com/H-BF/protos/pkg/api/sgroups"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

var (
	firstCidr  = "10.10.10.0/24"
	secondCidr = "20.20.20.0/24"
	thirdCidr  = "30.30.30.0/24"
)

type (
	networkData struct {
		name string
		cidr string
	}
)

func TestAccNetworks(t *testing.T) {
	rName1 := acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum)
	rName2 := acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum)

	if net := getNetwork(rName1, t); net != nil {
		t.Errorf("there are network %s already", rName1)
	}

	if net := getNetwork(rName2, t); net != nil {
		t.Errorf("there are network %s already", rName1)
	}

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: networkConfig(networkData{name: rName1, cidr: firstCidr}, networkData{name: rName2, cidr: secondCidr}),
				Check: func(tState *terraform.State) error {
					net := getNetwork(rName1, t)
					if net == nil {
						return fmt.Errorf("network %s not found", rName1)
					}
					if net.GetNetwork().CIDR != firstCidr {
						return fmt.Errorf("network CIDR %s differs from configured %s", net.GetNetwork().CIDR, firstCidr)
					}

					net = getNetwork(rName2, t)
					if net == nil {
						return fmt.Errorf("network %s not found", rName2)
					}
					if net.GetNetwork().CIDR != secondCidr {
						return fmt.Errorf("network CIDR %s differs from configured %s", net.GetNetwork().CIDR, secondCidr)
					}
					return nil
				},
			},
			{
				Config: networkConfig(networkData{name: rName1, cidr: thirdCidr}),
				Check: func(tState *terraform.State) error {
					net := getNetwork(rName1, t)
					if net == nil {
						return fmt.Errorf("network %s not found", rName1)
					}
					if net.GetNetwork().CIDR != thirdCidr {
						return fmt.Errorf("network CIDR %s differs from configured %s", net.GetNetwork().CIDR, thirdCidr)
					}

					net = getNetwork(rName2, t)
					if net != nil {
						return fmt.Errorf("network %s should be deleted", rName2)
					}
					return nil
				},
			},
		},
	})

}

func getNetwork(netName string, t *testing.T) *protos.Network {
	resp, err := testAccSgClient.ListNetworks(context.Background(), &protos.ListNetworksReq{
		NeteworkNames: []string{netName},
	})
	if err != nil {
		t.Errorf("list networks: %v", err)
	}

	if len(resp.GetNetworks()) == 0 {
		return nil
	}

	return resp.GetNetworks()[0]
}

func networkConfig(net1 networkData, others ...networkData) string {
	var (
		networksTemplate = `
resource "sgroups_networks" "test" {
	items = {
		%s
	}
}`
		networkItemTemplate = `
		"%s" = {
			name = "%s"
			cidr = "%s"
		}
`
	)
	items := strings.Builder{}
	items.WriteString(fmt.Sprintf(networkItemTemplate, net1.name, net1.name, net1.cidr))
	for _, i := range others {
		items.WriteString(fmt.Sprintf(networkItemTemplate, i.name, i.name, i.cidr))
	}

	return fmt.Sprintf(networksTemplate, items.String())
}
