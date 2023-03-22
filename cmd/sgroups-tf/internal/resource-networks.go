package internal

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"

	utils "github.com/H-BF/sgroups/internal/api/sgroups"
	model "github.com/H-BF/sgroups/internal/models/sgroups"

	"github.com/H-BF/corlib/pkg/slice"
	"github.com/H-BF/protos/pkg/api/common"
	sgroupsAPI "github.com/H-BF/protos/pkg/api/sgroups"
	"github.com/hashicorp/go-cty/cty"
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
- name: nw1
  cidr: 1.1.1.0/24
- name: nw2
  cidr: 2.2.2.0/24
*/

// SGroupsRcNetworks networks resource
func SGroupsRcNetworks() *schema.Resource {
	return &schema.Resource{
		Description: fmt.Sprintf("represents networks resource in '%s' provider", SGroupsProvider),
		CreateContext: func(ctx context.Context, rd *schema.ResourceData, i interface{}) diag.Diagnostics {
			return networksUpd(ctx, rd, i, false)
		},
		UpdateContext: func(ctx context.Context, rd *schema.ResourceData, i interface{}) diag.Diagnostics {
			return networksUpd(ctx, rd, i, true)
		},
		DeleteContext: networksDelete,
		ReadContext:   networksRead,
		Schema: map[string]*schema.Schema{
			RcLabelItems: {
				Optional: true,
				//ForceNew:    true,
				Description: "newtwork list",
				Type:        schema.TypeList,
				Elem: &schema.Resource{
					Description: "network element",
					Schema: map[string]*schema.Schema{
						RcLabelName: {
							Description: "network name",
							Type:        schema.TypeString,
							Required:    true,
						},
						RcLabelCIDR: {
							Description: "network in 'CIDR' format",
							Type:        schema.TypeString,
							Required:    true,
							ValidateDiagFunc: func(v interface{}, p cty.Path) diag.Diagnostics {
								s := v.(string)
								if _, _, err := net.ParseCIDR(s); err != nil {
									return diag.Diagnostics{{
										Severity:      diag.Error,
										Summary:       err.Error(),
										Detail:        fmt.Sprintf("bad CIDR '%s'", s),
										AttributePath: p,
									}}
								}
								return nil
							},
						},
					},
				},
			},
		},
	}
}

func networksRead(ctx context.Context, rd *schema.ResourceData, i interface{}) diag.Diagnostics {
	resp, err := i.(SGClient).ListNetworks(ctx, new(sgroupsAPI.ListNetworksReq))
	if err != nil {
		return diag.FromErr(err)
	}
	var items []any
	var names []string
	for _, n := range resp.GetNetworks() {
		var nw model.Network
		if nw, err = utils.Proto2ModelNetwork(n); err != nil {
			return diag.FromErr(err)
		}
		items = append(items, map[string]any{
			RcLabelName: nw.Name,
			RcLabelCIDR: nw.Net.String(),
		})
		names = append(names, nw.Name)
	}
	rd.Set(RcLabelItems, items)
	if len(names) == 0 {
		rd.SetId("<none>")
	} else {
		rd.SetId(strings.Join(names, ";"))
	}
	return nil
}

func networksUpd(ctx context.Context, rd *schema.ResourceData, i interface{}, fullSync bool) diag.Diagnostics {
	raw, ok := rd.GetOk(RcLabelItems)
	var names []string
	var nws []*sgroupsAPI.Network
	if ok {
		items := raw.([]interface{})
		for _, item := range items {
			it := item.(map[string]interface{})
			name := it[RcLabelName].(string)
			cidr := it[RcLabelCIDR].(string)
			names = append(names, strings.ToLower(name))
			nws = append(nws, &sgroupsAPI.Network{
				Name:    name,
				Network: &common.Networks_NetIP{CIDR: cidr},
			})
		}
		sort.Strings(names)
		_ = slice.DedupSlice(&names, func(i, j int) bool {
			return names[i] == names[j]
		})
	}

	op := sgroupsAPI.SyncReq_Upsert
	if fullSync {
		op = sgroupsAPI.SyncReq_FullSync
	}
	req := sgroupsAPI.SyncReq{
		SyncOp: op,
		Subject: &sgroupsAPI.SyncReq_Networks{
			Networks: &sgroupsAPI.SyncNetworks{
				Networks: nws,
			},
		},
	}
	_, err := i.(SGClient).Sync(ctx, &req)
	if err != nil {
		return diag.FromErr(err)
	}
	if len(names) == 0 {
		rd.SetId("<none>")
	} else {
		rd.SetId(strings.Join(names, ";"))
	}
	return nil
}

func networksDelete(ctx context.Context, rd *schema.ResourceData, i interface{}) diag.Diagnostics {
	raw, ok := rd.GetOk(RcLabelItems)
	if !ok {
		return nil
	}
	items := raw.([]interface{})
	if len(items) == 0 {
		return nil
	}
	var nws []*sgroupsAPI.Network
	for _, item := range items {
		it := item.(map[string]interface{})
		nws = append(nws, &sgroupsAPI.Network{
			Name: it[RcLabelName].(string),
		})
	}
	req := sgroupsAPI.SyncReq{
		SyncOp: sgroupsAPI.SyncReq_Delete,
		Subject: &sgroupsAPI.SyncReq_Networks{
			Networks: &sgroupsAPI.SyncNetworks{
				Networks: nws,
			},
		},
	}
	_, err := i.(SGClient).Sync(ctx, &req)
	return diag.FromErr(err)
}
