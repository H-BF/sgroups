package provider

import (
	"context"
	"fmt"
	"testing"

	protos "github.com/H-BF/protos/pkg/api/sgroups"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

/*//TODO: в общем тесты выглядят как булшит
                     начинаем раунды исправлений
1. изучаем пакет https://pkg.go.dev/github.com/stretchr/testify/suite
   - создаем базовый съют
     - там инициализируем провайдер
	 - всё что в provider_test.go/var/init  = л и к в и д и р у е м
	 - testutils.go test-data-utils.go = в корзину
   - для каждого ресурса от создаем съют от базового
     - делаем съют-тест
2. конфиги типа networksConfig sgSgRulesConfig - в топку, делаем всё через фикстуры
   - фикстуры пишем в папку ./fixtures
     как работать с фикстурами - есть пример в этой-же папке
*/

var (
	firstCidr  = "10.10.10.0/24"
	secondCidr = "20.20.20.0/24"
	thirdCidr  = "30.30.30.0/24"
)

func TestAccNetworks(t *testing.T) {
	ctx := context.Background()
	rName1 := acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum)
	rName2 := acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum)

	if net := getNetwork(ctx, t, rName1); net != nil {
		t.Errorf("there are network %s already", rName1)
	}

	if net := getNetwork(ctx, t, rName2); net != nil {
		t.Errorf("there are network %s already", rName1)
	}

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: networksConfig(networkTestData{name: rName1, cidr: firstCidr}, networkTestData{name: rName2, cidr: secondCidr}),
				Check: func(tState *terraform.State) error {
					net := getNetwork(ctx, t, rName1)
					if net == nil {
						return fmt.Errorf("network %s not found", rName1)
					}
					if net.GetNetwork().CIDR != firstCidr {
						return fmt.Errorf("network CIDR %s differs from configured %s", net.GetNetwork().CIDR, firstCidr)
					}

					net = getNetwork(ctx, t, rName2)
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
				Config: networksConfig(networkTestData{name: rName1, cidr: thirdCidr}),
				Check: func(tState *terraform.State) error {
					net := getNetwork(ctx, t, rName1)
					if net == nil {
						return fmt.Errorf("network %s not found", rName1)
					}
					if net.GetNetwork().CIDR != thirdCidr {
						return fmt.Errorf("network CIDR %s differs from configured %s", net.GetNetwork().CIDR, thirdCidr)
					}

					net = getNetwork(ctx, t, rName2)
					if net != nil {
						return fmt.Errorf("network %s should be deleted", rName2)
					}
					return nil
				},
			},
		},
	})

}

func getNetwork(ctx context.Context, t *testing.T, netName string) *protos.Network {
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

func networksConfig(fst testDataItem, others ...testDataItem) string {
	return buildConfig(networksTemplate, fst, others...)
}
