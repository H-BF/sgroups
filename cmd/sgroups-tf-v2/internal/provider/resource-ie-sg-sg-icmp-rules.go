package provider

import (
	"context"
	"fmt"
	"math"
	"strings"

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

func NewIESgSgIcmpRulesResource() resource.Resource {
	d := Description{
		ResourceDescription: "mapped 'icmp<4|6>:sg-local(local_sg)sg(external_sg)traffic' -> '<IN|E>GRESS:SG-SG:ICMP' rule resource",
		ItemsDescription:    "<IN|E>GRESS SG -> SG ICMP rules",
	}

	return &ieSgSgIcmpRulesResource{
		suffix:      "_ie_icmp_rules",
		description: d,
		readState:   readIESgSgIcmpRules,
	}
}

type (
	ieSgSgIcmpRulesResource = CollectionResource[ieSgSgIcmpRule, tfIESgSgIcmpRules2Backend]
	ieSgSgIcmpRule          struct {
		Traffic   types.String `tfsdk:"traffic"`
		SgLocal   types.String `tfsdk:"sg_local"`
		Sg        types.String `tfsdk:"sg"`
		Type      types.Set    `tfsdk:"type"`
		IpVersion types.String `tfsdk:"ip_v"`
		Logs      types.Bool   `tfsdk:"logs"`
		Trace     types.Bool   `tfsdk:"trace"`
		Action    types.String `tfsdk:"action"`
		Priority  RulePriority `tfsdk:"priority"`
	}

	ieSgSgIcmpRuleKey struct {
		ipVersion string
		sgLocal   string
		sg        string
		traffic   string
	}
)

// String -
func (k ieSgSgIcmpRuleKey) String() string {
	versions := map[string]uint{"IPv4": 4, "IPv6": 6}
	ver, ok := versions[k.ipVersion]
	if !ok {
		panic("unreachable: check `IpVersion` field validation in resource schema for exhaustiveness")
	}
	return fmt.Sprintf("icmp%v:sg-local(%s)sg(%s)%s",
		ver, k.sgLocal, k.sg, k.traffic)
}

// Key -
func (item ieSgSgIcmpRule) Key() *ieSgSgIcmpRuleKey {
	return &ieSgSgIcmpRuleKey{
		ipVersion: item.IpVersion.ValueString(),
		sgLocal:   item.SgLocal.ValueString(),
		sg:        item.Sg.ValueString(),
		traffic:   item.Traffic.ValueString(),
	}
}

func (item ieSgSgIcmpRule) Attributes() map[string]schema.Attribute {
	return map[string]schema.Attribute{
		"traffic": schema.StringAttribute{
			Description: "direction of traffic <ingress|egress>",
			Required:    true,
			Validators: []validator.String{
				stringvalidator.OneOf("ingress", "egress"),
			},
		},
		"sg_local": schema.StringAttribute{
			Description: "Security Group name of dst/src group when ingress/egress traffic chosen",
			Required:    true,
		},
		"sg": schema.StringAttribute{
			Description: "Security Group name of opposite group to sg_local",
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
		rulePriorityAttrLabel: rulePriorityAttr(),
	}
}

func (item ieSgSgIcmpRule) icmp2Proto(ctx context.Context, diags *diag.Diagnostics) *common.ICMP {
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

func (item ieSgSgIcmpRule) IsDiffer(_ context.Context, other ieSgSgIcmpRule) bool { //nolint:dupl
	return !(item.Traffic.Equal(other.Traffic) &&
		item.SgLocal.Equal(other.SgLocal) &&
		item.Sg.Equal(other.Sg) &&
		item.Type.Equal(other.Type) &&
		item.IpVersion.Equal(other.IpVersion) &&
		item.Logs.Equal(other.Logs) &&
		item.Trace.Equal(other.Trace) &&
		item.Action.Equal(other.Action) &&
		item.Priority.Equal(other.Priority))
}

func readIESgSgIcmpRules(
	ctx context.Context, state NamedResources[ieSgSgIcmpRule], client *sgAPI.Client,
) (NamedResources[ieSgSgIcmpRule], diag.Diagnostics) {
	var diags diag.Diagnostics
	newState := NewNamedResources[ieSgSgIcmpRule]()
	var resp *protos.IESgSgIcmpRulesResp
	var err error
	if len(state.Items) > 0 {
		req := new(protos.FindIESgSgIcmpRulesReq)
		linq.From(state.Items).
			SelectT(func(i linq.KeyValue) string {
				return i.Value.(ieSgSgIcmpRule).SgLocal.ValueString()
			}).Distinct().ToSlice(&req.SgLocal)
		linq.From(state.Items).
			SelectT(func(i linq.KeyValue) string {
				return i.Value.(ieSgSgIcmpRule).Sg.ValueString()
			}).Distinct().ToSlice(&req.Sg)
		if resp, err = client.FindIESgSgIcmpRules(ctx, req); err != nil {
			diags.AddError("read ie-sg-sg icmp rules", err.Error())
			return newState, diags
		}
	}

	for _, icmpRule := range resp.GetRules() { //nolint:dupl
		it := ieSgSgIcmpRule{
			Traffic:   types.StringValue(strings.ToLower(icmpRule.GetTraffic().String())),
			SgLocal:   types.StringValue(icmpRule.GetSgLocal()),
			Sg:        types.StringValue(icmpRule.GetSg()),
			IpVersion: types.StringValue(icmpRule.ICMP.GetIPv().String()),
		}
		k := it.Key().String()
		if _, ok := state.Items[k]; ok {
			if p, d := rulePriorityFromProto(icmpRule.GetPriority()); d != nil {
				diags.Append(d)
				break
			} else {
				it.Priority = p
			}
			typeSet, d := types.SetValueFrom(ctx, types.Int64Type, icmpRule.ICMP.GetTypes())
			diags.Append(d...)
			if d.HasError() {
				return newState, diags
			}
			it.Type = typeSet
			it.Logs = types.BoolValue(icmpRule.GetLogs())
			it.Trace = types.BoolValue(icmpRule.GetTrace())
			it.Action = types.StringValue(icmpRule.GetAction().String())
			newState.Items[k] = it
		}
	}
	return newState, diags
}
