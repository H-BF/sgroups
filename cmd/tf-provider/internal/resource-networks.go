package internal

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/H-BF/corlib/pkg/slice"
	"github.com/H-BF/protos/pkg/api/common"
	sgroupsAPI "github.com/H-BF/protos/pkg/api/sgroups"
	"github.com/hashicorp/go-cty/cty"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// RcLabelNetworks -
const RcLabelNetworks = "networks"

// RcLabelItems -
const RcLabelItems = "items"

// RcLabelName -
const RcLabelName = "name"

// RcLabelCIDR -
const RcLabelCIDR = "cidr"

// SGroupsRcNetworks networks resource
func SGroupsRcNetworks() *schema.Resource {
	return &schema.Resource{
		Description:   fmt.Sprintf("represent networks resource in '%s' provider", SGroupsProvider),
		CreateContext: networksUpsert,
		UpdateContext: networksUpsert,
		DeleteContext: networksDelete,
		Schema: map[string]*schema.Schema{
			RcLabelItems: {
				Description: "newtwork list",
				Type:        schema.TypeList,
				Required:    true,
				MinItems:    1,
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

func networksUpsert(ctx context.Context, rd *schema.ResourceData, i interface{}) diag.Diagnostics {
	items := rd.Get(RcLabelItems).([]interface{})
	var names []string
	var nws []*sgroupsAPI.Network
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
	req := sgroupsAPI.SyncReq{
		SyncOp: sgroupsAPI.SyncReq_Upsert,
		Subject: &sgroupsAPI.SyncReq_Networks{
			Networks: &sgroupsAPI.SyncNetworks{
				Networks: nws,
			},
		},
	}
	c := i.(SGClient)
	_, err := c.Sync(ctx, &req)
	if err != nil {
		return diag.FromErr(err)
	}
	rd.SetId(strings.Join(names, ";"))
	return nil
}

func networksDelete(ctx context.Context, rd *schema.ResourceData, i interface{}) diag.Diagnostics {
	items := rd.Get(RcLabelItems).([]interface{})
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
	c := i.(SGClient)
	_, err := c.Sync(ctx, &req)
	return diag.FromErr(err)
}