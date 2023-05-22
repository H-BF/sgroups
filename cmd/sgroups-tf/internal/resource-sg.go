package internal

import (
	"bytes"
	"context"
	"sort"
	"strings"

	"github.com/H-BF/corlib/pkg/slice"
	utils "github.com/H-BF/sgroups/internal/api/sgroups"

	sgroupsAPI "github.com/H-BF/protos/pkg/api/sgroups"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// RcSG -
const RcSG = SGroupsProvider + "_group"

// SGroupsRcSG SG resource
func SGroupsRcSG() *schema.Resource {
	return &schema.Resource{
		Description:   "SecurityGroup resource",
		ReadContext:   sgRead,
		CreateContext: sgC,
		UpdateContext: func(ctx context.Context, rd *schema.ResourceData, i interface{}) diag.Diagnostics {
			return sgUD(ctx, rd, i, true)
		},
		DeleteContext: func(ctx context.Context, rd *schema.ResourceData, i interface{}) diag.Diagnostics {
			return sgUD(ctx, rd, i, false)
		},
		Schema: map[string]*schema.Schema{
			RcLabelName: {
				Description: "SecurityGroup name",
				Type:        schema.TypeString,
				Required:    true,
			},
			RcLabelNetworks: {
				DiffSuppressFunc: func(_, oldValue, newValue string, _ *schema.ResourceData) bool {
					a := strings.Join(splitNetNames(oldValue), ",")
					b := strings.Join(splitNetNames(newValue), ",")
					return a == b
				},
				DiffSuppressOnRefresh: true,
				Description:           "associated set of network(s)",
				Type:                  schema.TypeString,
				Optional:              true,
			},
		},
	}
}

func sgRead(ctx context.Context, rd *schema.ResourceData, i interface{}) diag.Diagnostics {
	name := rd.Get(RcLabelName).(string)
	resp, err := i.(SGClient).ListSecurityGroups(ctx, &sgroupsAPI.ListSecurityGroupsReq{
		SgNames: []string{name},
	})
	if err != nil {
		return diag.FromErr(err)
	}
	if g := resp.GetGroups(); len(g) > 0 {
		m := utils.Proto2BriefModelSG(g[0])
		if err = rd.Set(RcLabelName, m.Name); err == nil {
			buf := bytes.NewBuffer(nil)
			for _, n := range m.Networks {
				if buf.Len() > 0 {
					_ = buf.WriteByte(',')
				}
				_, _ = buf.WriteString(n)
			}
			err = rd.Set(RcLabelNetworks, buf.String())
		}
	} else {
		rd.SetId("")
	}
	return diag.FromErr(err)
}

func sgC(ctx context.Context, rd *schema.ResourceData, i interface{}) diag.Diagnostics {
	name := rd.Get(RcLabelName).(string)
	nwList, _ := rd.Get(RcLabelNetworks).(string)
	sg := &sgroupsAPI.SecGroup{
		Name:     name,
		Networks: splitNetNames(nwList),
	}
	req := sgroupsAPI.SyncReq{
		SyncOp: sgroupsAPI.SyncReq_Upsert,
		Subject: &sgroupsAPI.SyncReq_Groups{
			Groups: &sgroupsAPI.SyncSecurityGroups{
				Groups: []*sgroupsAPI.SecGroup{sg},
			},
		},
	}
	if _, err := i.(SGClient).Sync(ctx, &req); err != nil {
		return diag.FromErr(err)
	}
	rd.SetId(name)
	return nil
}

func sgUD(ctx context.Context, rd *schema.ResourceData, i interface{}, upd bool) diag.Diagnostics {
	if upd && rd.HasChange(RcLabelName) {
		return diag.Errorf("unable change 'name' for 'SG' resource")
	}
	name := rd.Get(RcLabelName).(string)
	sg := &sgroupsAPI.SecGroup{
		Name: name,
	}
	if upd {
		nwList, _ := rd.Get(RcLabelNetworks).(string)
		sg.Networks = splitNetNames(nwList)
	}
	op := sgroupsAPI.SyncReq_Upsert
	if !upd {
		op = sgroupsAPI.SyncReq_Delete
	}
	req := sgroupsAPI.SyncReq{
		SyncOp: op,
		Subject: &sgroupsAPI.SyncReq_Groups{
			Groups: &sgroupsAPI.SyncSecurityGroups{
				Groups: []*sgroupsAPI.SecGroup{sg},
			},
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

func splitNetNames(s string) []string {
	var l []string
	for _, item := range strings.Split(s, ",") {
		if x := strings.TrimSpace(item); len(x) > 0 {
			l = append(l, x)
		}
	}
	sort.Strings(l)
	_ = slice.DedupSlice(&l, func(i, j int) bool {
		return l[i] == l[j]
	})
	return l
}
