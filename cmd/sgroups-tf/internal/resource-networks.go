package internal

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"strings"

	utils "github.com/H-BF/sgroups/internal/api/sgroups"
	model "github.com/H-BF/sgroups/internal/models/sgroups"

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
		Description:   fmt.Sprintf("represents networks resource in '%s' provider", SGroupsProvider),
		CreateContext: networksIns,
		UpdateContext: networksUpd,
		DeleteContext: networksDelete,
		ReadContext:   networksRead,
		Schema: map[string]*schema.Schema{
			RcLabelItems: {
				Optional:    true,
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
	oldId := rd.Id()
	if len(oldId) == 0 {
		return nil
	}
	var helper resourceKey[model.Network]
	helper.init(oldId, ";")
	resp, err := i.(SGClient).ListNetworks(ctx, new(sgroupsAPI.ListNetworksReq))
	if err != nil {
		return diag.FromErr(err)
	}
	srcNetworks := resp.GetNetworks()
	for _, n := range srcNetworks {
		var nw model.Network
		if nw, err = utils.Proto2ModelNetwork(n); err != nil {
			return diag.FromErr(err)
		}
		helper.set(nw.Name, &nw)
	}
	var items []any
	helper.walk(func(k string, nw *model.Network) bool {
		if nw != nil {
			items = append(items, map[string]any{
				RcLabelName: nw.Name,
				RcLabelCIDR: nw.Net.String(),
			})
		} else {
			items = append(items, nil)
		}
		return true
	})
	//rd.SetId(helper.ID())
	return diag.FromErr(
		rd.Set(RcLabelItems, items),
	)
}

func networksIns(ctx context.Context, rd *schema.ResourceData, i interface{}) diag.Diagnostics {
	var h resourceKey[sgroupsAPI.Network]
	h.init("", ";")
	if raw, ok := rd.GetOk(RcLabelItems); ok {
		items := raw.([]interface{})
		for _, item := range items {
			it := item.(map[string]interface{})
			name := it[RcLabelName].(string)
			cidr := it[RcLabelCIDR].(string)
			h.add(name, &sgroupsAPI.Network{
				Name:    name,
				Network: &common.Networks_NetIP{CIDR: cidr},
			})
		}
	}

	req := sgroupsAPI.SyncReq{
		SyncOp: sgroupsAPI.SyncReq_Upsert,
		Subject: &sgroupsAPI.SyncReq_Networks{
			Networks: &sgroupsAPI.SyncNetworks{
				Networks: h.objects(true),
			},
		},
	}
	if _, err := i.(SGClient).Sync(ctx, &req); err != nil {
		return diag.FromErr(err)
	}
	rd.SetId(h.ID())
	return nil
}

func networksUpd(ctx context.Context, rd *schema.ResourceData, i interface{}) diag.Diagnostics {
	oldRaw, newRaw := rd.GetChange(RcLabelItems)
	var h resourceKey[sgroupsAPI.Network]
	h.init("", ";")
	_ = newRaw
	itemsOld := oldRaw.([]interface{})
	itemsNew := newRaw.([]interface{})
	for i := range itemsOld {
		itemOld := itemsOld[i]
		itemNew := itemsNew[i]
		if itemOld == nil {
			continue
		}
		if itemNew == nil {
			continue
		}
		it := itemNew.(map[string]interface{})
		name := it[RcLabelName].(string)
		cidr := it[RcLabelCIDR].(string)
		h.add(name, &sgroupsAPI.Network{
			Name:    name,
			Network: &common.Networks_NetIP{CIDR: cidr},
		})
	}
	req := sgroupsAPI.SyncReq{
		SyncOp: sgroupsAPI.SyncReq_Upsert,
		Subject: &sgroupsAPI.SyncReq_Networks{
			Networks: &sgroupsAPI.SyncNetworks{
				Networks: h.objects(true),
			},
		},
	}
	if _, err := i.(SGClient).Sync(ctx, &req); err != nil {
		return diag.FromErr(err)
	}
	rd.SetId(h.ID())
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

type resourceKey[T any] struct {
	source []string
	mapped map[string]*T
	sep    string
}

// ID -
func (rk *resourceKey[T]) ID() string {
	buf := bytes.NewBuffer(nil)
	rk.walk(func(k string, obj *T) bool {
		if obj != nil {
			if buf.Len() > 0 {
				_, _ = buf.WriteString(rk.sep)
			}
			_, _ = buf.WriteString(k)
		}
		return true
	})
	return buf.String()
	//return strings.Join(rk.source, rk.sep)
}

func (rk *resourceKey[T]) set(k string, obj *T) bool {
	k = strings.TrimSpace(k)
	_, occupied := rk.mapped[k]
	if occupied {
		rk.mapped[k] = obj
	}
	return occupied
}

func (rk *resourceKey[T]) add(k string, obj *T) bool {
	k = strings.TrimSpace(k)
	_, occupied := rk.mapped[k]
	if !occupied {
		rk.mapped[k] = obj
		rk.source = append(rk.source, k)
	}
	return !occupied
}

func (rk *resourceKey[T]) init(keys string, sep string) {
	rk.sep = sep
	sp := strings.Split(keys, sep)
	rk.source = rk.source[:0]
	rk.mapped = make(map[string]*T)
	for _, s := range sp {
		if s = strings.TrimSpace(s); len(s) > 0 {
			if _, ok := rk.mapped[s]; ok {
				continue
			}
			rk.source = append(rk.source, s)
			rk.mapped[s] = nil
		}
	}
}

func (rk *resourceKey[T]) walk(f func(k string, obj *T) bool) {
	for _, k := range rk.source {
		if !f(k, rk.mapped[k]) {
			break
		}
	}
}

func (rk *resourceKey[T]) objects(nonNils bool) []*T {
	var ret []*T
	rk.walk(func(_ string, obj *T) bool {
		if !nonNils || obj != nil {
			ret = append(ret, obj)
		}
		return true
	})
	return ret
}
