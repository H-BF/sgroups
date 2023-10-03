package internal

import (
	"context"
	"fmt"

	"github.com/H-BF/protos/pkg/api/common"
	sgroupsAPI "github.com/H-BF/protos/pkg/api/sgroups"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

const (
	// RcNetworks -
	RcNetworks = SGroupsProvider + "_networks"

	// RcLabelNetworks -
	RcLabelNetworks = "networks"

	// RcLabelItems -
	RcLabelItems = "items"

	// RcLabelName -
	RcLabelName = "name"

	// RcLabelCIDR -
	RcLabelCIDR = "cidr"
)

/*// resource skeleton
items:
- nw1
    cidr: 1.1.1.0/24
- nw2
    cidr: 2.2.2.0/24
*/

// SGroupsRcNetworks networks resource
func SGroupsRcNetworks() *schema.Resource {
	itemRC := SGroupsRcNetwork()
	itemRC.CreateContext = nil
	itemRC.UpdateContext = nil
	itemRC.CreateContext = nil
	itemRC.DeleteContext = nil
	delete(itemRC.Schema, RcLabelName) //use Name as the MapKey
	return &schema.Resource{
		Description:   fmt.Sprintf("represents networks resource in '%s' provider", SGroupsProvider),
		CreateContext: networksC,
		UpdateContext: networksU,
		DeleteContext: networksD,
		ReadContext:   networksR,
		Schema: map[string]*schema.Schema{
			RcLabelItems: {
				Optional:    true,
				Description: "newtworks",
				Type:        schema.TypeMap,
				Elem:        itemRC,
			},
		},
	}
}

type crudNetworks = listedRcCRUD[
	sgroupsAPI.Network,
	anyConstructorWithKey[sgroupsAPI.Network],
]

func networksR(ctx context.Context, rd *schema.ResourceData, i interface{}) diag.Diagnostics {
	var h listedResource[sgroupsAPI.Network]
	h.init("", ";")
	if err := (crudNetworks{}).fillListedResource(rd.Get(RcLabelItems), &h); err != nil {
		return diag.FromErr(err)
	}
	if len(h.mapped) == 0 {
		rd.SetId(noneID)
		return nil
	}
	var req sgroupsAPI.ListNetworksReq
	h.walk(func(k string, _ *sgroupsAPI.Network) bool {
		req.NeteworkNames = append(req.NeteworkNames, k)
		h.set(k, nil)
		return true
	})
	resp, err := i.(SGClient).ListNetworks(ctx, &req)
	if err != nil {
		return diag.FromErr(err)
	}
	for _, n := range resp.GetNetworks() {
		h.set(n.GetName(), n)
	}
	items := make(map[string]any)
	h.walk(func(_ string, nw *sgroupsAPI.Network) bool {
		if nw != nil {
			items[nw.GetName()] = map[string]any{
				RcLabelCIDR: nw.GetNetwork().GetCIDR(),
			}
		}
		return true
	})
	rd.SetId(h.id(noneID))
	return diag.FromErr(
		rd.Set(RcLabelItems, items),
	)
}

func networksC(ctx context.Context, rd *schema.ResourceData, i interface{}) diag.Diagnostics {
	crud := crudNetworks{tf2proto: tf2protoNetwork, labelItems: RcLabelItems, client: i.(SGClient)}
	return diag.FromErr(crud.create(ctx, rd))
}

func networksU(ctx context.Context, rd *schema.ResourceData, i interface{}) diag.Diagnostics {
	crud := crudNetworks{tf2proto: tf2protoNetwork, labelItems: RcLabelItems, client: i.(SGClient)}
	return diag.FromErr(crud.update(ctx, rd))
}

func networksD(ctx context.Context, rd *schema.ResourceData, i interface{}) diag.Diagnostics {
	crud := crudNetworks{tf2proto: tf2protoNetwork, labelItems: RcLabelItems, client: i.(SGClient)}
	return diag.FromErr(crud.delete(ctx, rd))
}

func tf2protoNetwork(key string, raw any) (string, *sgroupsAPI.Network, error) {
	it := raw.(map[string]any)
	return key, &sgroupsAPI.Network{
		Name: key,
		Network: &common.Networks_NetIP{
			CIDR: it[RcLabelCIDR].(string),
		},
	}, nil
}
