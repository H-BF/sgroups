package provider

import (
	"context"
	"fmt"

	"github.com/H-BF/protos/pkg/api/common"
	protos "github.com/H-BF/protos/pkg/api/sgroups"
	sgAPI "github.com/H-BF/sgroups/internal/api/sgroups"

	"github.com/ahmetb/go-linq/v3"
	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func NewSgToSgIcmpRulesResource() resource.Resource {
	d := Description{
		ResourceDescription: "mapped 'sg(sg-from)sg(sg-to)icmp4/6' -> 'SG-SG' ICMP rule resource",
		ItemsDescription:    "SG to SG ICMP rules",
	}
	return &sgSgIcmpRulesResource{
		suffix:       "_icmp_rules",
		description:  d,
		toSubjOfSync: sgSgIcmpRules2SyncSubj,
		read:         readSgSgIcmpRules,
	}
}

type (
	sgSgIcmpRulesResource = CollectionResource[sgSgIcmpRule, protos.SyncSgSgIcmpRules]

	sgSgIcmpRulesResourceModel = CollectionResourceModel[sgSgIcmpRule, protos.SyncSgSgIcmpRules]

	sgSgIcmpRule struct {
		SgFrom    types.String `tfsdk:"sg_from"`
		SgTo      types.String `tfsdk:"sg_to"`
		Type      types.Set    `tfsdk:"type"`
		IpVersion types.String `tfsdk:"ip_v"`
		Logs      types.Bool   `tfsdk:"logs"`
		Trace     types.Bool   `tfsdk:"trace"`
	}

	sgSgIcmpRuleKey struct {
		ipVersion string
		sgFrom    string
		sgTo      string
	}
)

func (k sgSgIcmpRuleKey) String() string {
	versions := map[string]uint{"IPv4": 4, "IPv6": 6}
	ver, ok := versions[k.ipVersion]
	if !ok {
		panic("unreachable: check `IpVersion` field validation in resource schema for exhaustiveness")
	}
	return fmt.Sprintf("sg(%s)sg(%s)icmp%v", k.sgFrom, k.sgTo, ver)
}

func (item sgSgIcmpRule) Key() *sgSgIcmpRuleKey {
	return &sgSgIcmpRuleKey{
		ipVersion: item.IpVersion.ValueString(),
		sgFrom:    item.SgFrom.ValueString(),
		sgTo:      item.SgTo.ValueString(),
	}
}

func (item sgSgIcmpRule) IsDiffer(other sgSgIcmpRule) bool {
	return !(item.SgFrom.Equal(other.SgFrom) &&
		item.SgTo.Equal(other.SgTo) &&
		item.Type.Equal(other.Type) &&
		item.IpVersion.Equal(other.IpVersion) &&
		item.Logs.Equal(other.Logs) &&
		item.Trace.Equal(other.Trace))
}

func (item sgSgIcmpRule) ResourceAttributes() map[string]schema.Attribute {
	return map[string]schema.Attribute{
		"sg_from": schema.StringAttribute{
			Description: "Security Group from",
			Required:    true,
		},
		"sg_to": schema.StringAttribute{
			Description: "Security Group to",
			Required:    true,
		},
		"type": schema.SetAttribute{
			Description: "Set of ICMP types",
			Required:    true,
			ElementType: types.Int64Type,
			Validators: []validator.Set{
				setvalidator.ValueInt64sAre(int64validator.Between(0, 255)),
			},
		},
		"ip_v": schema.StringAttribute{
			Description: "IP version",
			Optional:    true,
			Computed:    true,
			Default:     stringdefault.StaticString("IPv4"),
			Validators: []validator.String{
				stringvalidator.OneOf("IPv4", "IPv6"),
			},
		},
		"logs": schema.BoolAttribute{
			Description: "toggle logging on every rule in security group",
			Optional:    true,
			Computed:    true,
			Default:     booldefault.StaticBool(false),
		},
		"trace": schema.BoolAttribute{
			Description: "toggle logging on every rule in security group",
			Optional:    true,
			Computed:    true,
			Default:     booldefault.StaticBool(false),
		},
	}
}

func (item sgSgIcmpRule) Icmp2Proto(ctx context.Context, diags diag.Diagnostics) *common.ICMP {
	ret := new(common.ICMP)

	switch item.IpVersion.ValueString() {
	case "IPv4":
		ret.IPv = common.IpAddrFamily_IPv4
	case "IPv6":
		ret.IPv = common.IpAddrFamily_IPv6
	default:
		panic("unreachable: check `IpVersion` field validation in resource schema for exhaustiveness")
	}
	diags.Append(item.Type.ElementsAs(ctx, &ret.Types, true)...)

	return ret
}

func sgSgIcmpRules2SyncSubj(ctx context.Context, items map[string]sgSgIcmpRule) (*protos.SyncSgSgIcmpRules, diag.Diagnostics) {
	syncObj := new(protos.SyncSgSgIcmpRules)
	var diags diag.Diagnostics
	for _, features := range items {
		icmp := features.Icmp2Proto(ctx, diags)
		if diags.HasError() {
			return nil, diags
		}
		syncObj.Rules = append(syncObj.Rules, &protos.SgSgIcmpRule{
			SgFrom: features.SgFrom.ValueString(),
			SgTo:   features.SgTo.ValueString(),
			ICMP:   icmp,
			Logs:   features.Logs.ValueBool(),
			Trace:  features.Trace.ValueBool(),
		})
	}

	return syncObj, diags
}

func readSgSgIcmpRules(ctx context.Context, state sgSgIcmpRulesResourceModel, client *sgAPI.Client) (sgSgIcmpRulesResourceModel, diag.Diagnostics) {
	var diags diag.Diagnostics
	newState := sgSgIcmpRulesResourceModel{Items: make(map[string]sgSgIcmpRule)}
	var resp *protos.SgSgIcmpRulesResp
	if len(state.Items) > 0 {
		req := new(protos.FindSgSgIcmpRulesReq)
		linq.From(state.Items).
			Select(func(i interface{}) interface{} {
				return i.(linq.KeyValue).Value.(sgSgIcmpRule).SgFrom.ValueString()
			}).Distinct().ToSlice(&req.SgFrom)
		linq.From(state.Items).
			Select(func(i interface{}) interface{} {
				return i.(linq.KeyValue).Value.(sgSgIcmpRule).SgTo.ValueString()
			}).Distinct().ToSlice(&req.SgTo)
		var err error
		if resp, err = client.FindSgSgIcmpRules(ctx, req); err != nil {
			diags.AddError("read sg-sg icmp rules", err.Error())
			return newState, diags
		}
	}
	for _, icmpRule := range resp.GetRules() {
		typeSet, d := types.SetValueFrom(ctx, types.Int64Type, icmpRule.ICMP.GetTypes())
		diags.Append(d...)
		if d.HasError() {
			return sgSgIcmpRulesResourceModel{}, diags
		}
		it := sgSgIcmpRule{
			SgFrom:    types.StringValue(icmpRule.GetSgFrom()),
			SgTo:      types.StringValue(icmpRule.GetSgTo()),
			Type:      typeSet,
			IpVersion: types.StringValue(icmpRule.ICMP.GetIPv().String()),
			Logs:      types.BoolValue(icmpRule.GetLogs()),
			Trace:     types.BoolValue(icmpRule.GetTrace()),
		}
		k := it.Key().String()
		if _, ok := state.Items[k]; ok {
			newState.Items[k] = it
		}
	}
	return newState, diags
}
