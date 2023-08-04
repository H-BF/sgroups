package internal

import (
	"context"
	"sort"
	"strings"

	"github.com/H-BF/corlib/pkg/slice"

	sgroupsAPI "github.com/H-BF/protos/pkg/api/sgroups"
	"github.com/hashicorp/go-cty/cty"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// RcSG -
const RcSG = SGroupsProvider + "_group"

const (
	// RcLabelTrace -
	RcLabelTrace = "trace"

	// RcLabelDefaultAction
	RcLabelDefaultAction = "default_action"
)

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
			RcLabelLogs: {
				Description: "switch ON|OFF logs on SG",
				Optional:    true,
				Default:     false,
				Type:        schema.TypeBool,
			},
			RcLabelTrace: {
				Description: "switch ON|OFF trace on SG",
				Optional:    true,
				Default:     false,
				Type:        schema.TypeBool,
			},
			RcLabelDefaultAction: {
				Default:     sgroupsAPI.SecGroup_DROP.String(),
				Optional:    true,
				Description: "set default action on SG",
				Type:        schema.TypeString,
				ValidateDiagFunc: func(i interface{}, _ cty.Path) diag.Diagnostics {
					s := i.(string)
					ok := sgroupsAPI.SecGroup_ACCEPT.String() == s ||
						sgroupsAPI.SecGroup_DROP.String() == s
					if ok {
						return nil
					}
					return diag.Errorf("unknown SG default action '%s'", s)
				},
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
		for k, v := range protoSG2tf(g[0]) {
			if err = rd.Set(k, v); err != nil {
				break
			}
		}
	} else {
		rd.SetId("")
	}
	return diag.FromErr(err)
}

func sgC(ctx context.Context, rd *schema.ResourceData, i interface{}) diag.Diagnostics {
	labs := [...]string{
		RcLabelName, RcLabelNetworks, RcLabelLogs, RcLabelTrace, RcLabelDefaultAction,
	}
	raw := make(map[string]any)
	for _, l := range labs {
		raw[l] = rd.Get(l)
	}
	name, sg, err := tf2protoSG(raw)
	if err != nil {
		return diag.FromErr(err)
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
	labs := [...]string{
		RcLabelName, RcLabelNetworks, RcLabelLogs, RcLabelTrace, RcLabelDefaultAction,
	}
	raw := make(map[string]any)
	for _, l := range labs {
		raw[l] = rd.Get(l)
	}
	name, sg, err := tf2protoSG(raw)
	if err != nil {
		return diag.FromErr(err)
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
