package internal

import (
	"context"
	"net"

	utils "github.com/H-BF/sgroups/internal/api/sgroups"
	model "github.com/H-BF/sgroups/internal/models/sgroups"

	"github.com/H-BF/protos/pkg/api/common"
	sgroupsAPI "github.com/H-BF/protos/pkg/api/sgroups"
	"github.com/hashicorp/go-cty/cty"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// RcNetwork -
const RcNetwork = SGroupsProvider + "_network"

func SGroupsRcNetwork() *schema.Resource {
	return &schema.Resource{
		Description:   "network resource",
		CreateContext: networkC,
		ReadContext:   networkR,
		UpdateContext: func(ctx context.Context, rd *schema.ResourceData, i interface{}) diag.Diagnostics {
			return networkUD(ctx, rd, i, true)
		},
		DeleteContext: func(ctx context.Context, rd *schema.ResourceData, i interface{}) diag.Diagnostics {
			return networkUD(ctx, rd, i, false)
		},
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
						return diag.Errorf("bad CIDR '%s': %s", s, err.Error())
					}
					return nil
				},
			},
		},
	}
}

func networkR(ctx context.Context, rd *schema.ResourceData, i interface{}) diag.Diagnostics {
	name := rd.Get(RcLabelName).(string)
	req := sgroupsAPI.ListNetworksReq{
		NeteworkNames: []string{name},
	}
	resp, err := i.(SGClient).ListNetworks(ctx, &req)
	if err != nil {
		return diag.FromErr(err)
	}
	if srcNetworks := resp.GetNetworks(); len(srcNetworks) > 0 {
		var nw model.Network
		if nw, err = utils.Proto2ModelNetwork(srcNetworks[0]); err != nil {
			return diag.FromErr(err)
		}
		if err = rd.Set(RcLabelName, nw.Name); err == nil {
			err = rd.Set(RcLabelCIDR, nw.Net.String())
		}
	} else {
		rd.SetId("")
	}
	return diag.FromErr(err)
}

func networkC(ctx context.Context, rd *schema.ResourceData, i interface{}) diag.Diagnostics {
	name := rd.Get(RcLabelName).(string)
	var sn sgroupsAPI.SyncNetworks
	sn.Networks = append(sn.Networks, &sgroupsAPI.Network{
		Name:    name,
		Network: &common.Networks_NetIP{CIDR: rd.Get(RcLabelCIDR).(string)},
	})
	req := sgroupsAPI.SyncReq{
		SyncOp: sgroupsAPI.SyncReq_Upsert,
		Subject: &sgroupsAPI.SyncReq_Networks{
			Networks: &sn,
		},
	}
	if _, err := i.(SGClient).Sync(ctx, &req); err != nil {
		return diag.FromErr(err)
	}
	rd.SetId(name)
	return nil
}

func networkUD(ctx context.Context, rd *schema.ResourceData, i interface{}, upd bool) diag.Diagnostics {
	if upd && rd.HasChange(RcLabelName) {
		return diag.Errorf("unable change 'name' for 'network' resource")
	}
	name := rd.Get(RcLabelName).(string)
	var sn sgroupsAPI.SyncNetworks
	sn.Networks = append(sn.Networks, &sgroupsAPI.Network{
		Name:    name,
		Network: &common.Networks_NetIP{CIDR: rd.Get(RcLabelCIDR).(string)},
	})
	op := sgroupsAPI.SyncReq_Upsert
	if !upd {
		op = sgroupsAPI.SyncReq_Delete
	}
	req := sgroupsAPI.SyncReq{
		SyncOp: op,
		Subject: &sgroupsAPI.SyncReq_Networks{
			Networks: &sn,
		},
	}
	if _, err := i.(SGClient).Sync(ctx, &req); err != nil {
		return diag.FromErr(err)
	}
	if upd {
		rd.SetId(name)
	}
	return nil
}
