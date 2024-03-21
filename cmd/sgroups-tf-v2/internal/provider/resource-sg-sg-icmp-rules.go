package provider

import (
	"context"
	"fmt"
	"math"

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
		ResourceDescription: "mapped 'sg(sg-from)sg(sg-to)icmp<4|6>' -> 'SG-SG' ICMP rule resource",
		ItemsDescription:    "SG to SG ICMP rules",
	}
	return &sgSgIcmpRulesResource{
		suffix:      "_icmp_rules",
		description: d,
		readState:   readSgSgIcmpRules,
	}
}

type (
	sgSgIcmpRulesResource = CollectionResource[sgSgIcmpRule, tfSgSgIcmpRules2Backend]

	sgSgIcmpRule struct {
		SgFrom    types.String `tfsdk:"sg_from"`
		SgTo      types.String `tfsdk:"sg_to"`
		Type      types.Set    `tfsdk:"type"`
		IpVersion types.String `tfsdk:"ip_v"`
		Logs      types.Bool   `tfsdk:"logs"`
		Trace     types.Bool   `tfsdk:"trace"`
		Action    types.String `tfsdk:"action"`
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

func (item sgSgIcmpRule) IsDiffer(ctx context.Context, other sgSgIcmpRule) bool {
	return !(item.SgFrom.Equal(other.SgFrom) &&
		item.SgTo.Equal(other.SgTo) &&
		item.Type.Equal(other.Type) &&
		item.IpVersion.Equal(other.IpVersion) &&
		item.Logs.Equal(other.Logs) &&
		item.Trace.Equal(other.Trace) &&
		item.Action.Equal(other.Action))
}

func (item sgSgIcmpRule) Attributes() map[string]schema.Attribute {
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
				setvalidator.ValueInt64sAre(int64validator.Between(0, math.MaxUint8)),
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
			Description: "toggle tracing on every rule in security group",
			Optional:    true,
			Computed:    true,
			Default:     booldefault.StaticBool(false),
		},
		"action": schema.StringAttribute{
			Description: "Rule action on packets in chain",
			Required:    true,
			Validators:  []validator.String{actionValidator},
		},
	}
}

func (item sgSgIcmpRule) icmp2Proto(ctx context.Context, diags *diag.Diagnostics) *common.ICMP {
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

func readSgSgIcmpRules(
	ctx context.Context, state NamedResources[sgSgIcmpRule], client *sgAPI.Client,
) (NamedResources[sgSgIcmpRule], diag.Diagnostics) {
	var diags diag.Diagnostics
	newState := NewNamedResources[sgSgIcmpRule]()
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
			return newState, diags
		}
		it := sgSgIcmpRule{
			SgFrom:    types.StringValue(icmpRule.GetSgFrom()),
			SgTo:      types.StringValue(icmpRule.GetSgTo()),
			Type:      typeSet,
			IpVersion: types.StringValue(icmpRule.ICMP.GetIPv().String()),
			Logs:      types.BoolValue(icmpRule.GetLogs()),
			Trace:     types.BoolValue(icmpRule.GetTrace()),
			Action:    types.StringValue(icmpRule.Action.String()),
		}
		k := it.Key().String()
		if _, ok := state.Items[k]; ok {
			newState.Items[k] = it
		}
	}
	return newState, diags
}
