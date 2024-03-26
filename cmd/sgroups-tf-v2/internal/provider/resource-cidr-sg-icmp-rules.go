package provider

import (
	"context"
	"fmt"
	"math"
	"strings"

	"github.com/H-BF/protos/pkg/api/common"
	protos "github.com/H-BF/protos/pkg/api/sgroups"
	"github.com/H-BF/sgroups/cmd/sgroups-tf-v2/internal/validators"
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

func NewCidrSgIcmpRulesResource() resource.Resource {
	d := Description{
		ResourceDescription: "mapped 'icmp<4|6>:cidr(cidr_name)sg(sg_name)traffic' -> '<IN|E>GRESS:CIDR-SG:ICMP' rule resource",
		ItemsDescription:    "<IN|E>GRESS CIDR -> SG ICMP rules",
	}
	return &cidrSgIcmpRulesResource{
		suffix:      "_cidr_icmp_rules",
		description: d,
		readState:   readCidrSgIcmpRules,
	}
}

type (
	cidrSgIcmpRulesResource = CollectionResource[cidrSgIcmpRule, tfCidrSgIcmpRules2Backend]

	cidrSgIcmpRule struct {
		Traffic   types.String `tfsdk:"traffic"`
		Cidr      types.String `tfsdk:"cidr"`
		SgName    types.String `tfsdk:"sg_name"`
		Type      types.Set    `tfsdk:"type"`
		IpVersion types.String `tfsdk:"ip_v"`
		Logs      types.Bool   `tfsdk:"logs"`
		Trace     types.Bool   `tfsdk:"trace"`
		Action    types.String `tfsdk:"action"`
		Priority  RulePriority `tfsdk:"priority"`
	}

	cidrSgIcmpRuleKey struct {
		ipVersion string
		cidr      string
		sgName    string
		traffic   string
	}
)

// String -
func (k cidrSgIcmpRuleKey) String() string {
	versions := map[string]uint{"IPv4": 4, "IPv6": 6}
	ver, ok := versions[k.ipVersion]
	if !ok {
		panic("unreachable: check `IpVersion` field validation in resource schema for exhaustiveness")
	}
	return fmt.Sprintf("icmp%v:cidr(%s)sg(%s)%s",
		ver, k.cidr, k.sgName, strings.ToLower(k.traffic))
}

// Key -
func (item cidrSgIcmpRule) Key() *cidrSgIcmpRuleKey {
	return &cidrSgIcmpRuleKey{
		ipVersion: item.IpVersion.ValueString(),
		cidr:      item.Cidr.ValueString(),
		sgName:    item.SgName.ValueString(),
		traffic:   item.Traffic.ValueString(),
	}
}

// Attributes -
func (item cidrSgIcmpRule) Attributes() map[string]schema.Attribute {
	return map[string]schema.Attribute{
		"traffic": schema.StringAttribute{
			Description: "direction of traffic <ingress|egress>",
			Required:    true,
			Validators: []validator.String{
				stringvalidator.OneOf("ingress", "egress"),
			},
		},
		"cidr": schema.StringAttribute{
			Description: "IP subnet",
			Required:    true,
			Validators: []validator.String{
				validators.IsCIDR(),
			},
		},
		"sg_name": schema.StringAttribute{
			Description: "Security Group name",
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

func (item cidrSgIcmpRule) icmp2Proto(ctx context.Context, diags *diag.Diagnostics) *common.ICMP {
	ret := new(common.ICMP)
	val := item.IpVersion.ValueString()
	if v, ok := common.IpAddrFamily_value[val]; !ok {
		diags.AddError("ICMP", fmt.Sprintf("bad value for IPv='%s'", val))
	} else {
		ret.IPv = common.IpAddrFamily(v)
		diags.Append(item.Type.ElementsAs(ctx, &ret.Types, true)...)
	}
	return ret
}

// IsDiffer -
func (item cidrSgIcmpRule) IsDiffer(_ context.Context, other cidrSgIcmpRule) bool { //nolint:dupl
	return !(item.Traffic.Equal(other.Traffic) &&
		item.Cidr.Equal(other.Cidr) &&
		item.SgName.Equal(other.SgName) &&
		item.Type.Equal(other.Type) &&
		item.IpVersion.Equal(other.IpVersion) &&
		item.Logs.Equal(other.Logs) &&
		item.Trace.Equal(other.Trace) &&
		item.Action.Equal(other.Action) &&
		item.Priority.Equal(other.Priority))
}

func readCidrSgIcmpRules(
	ctx context.Context, state NamedResources[cidrSgIcmpRule], client *sgAPI.Client,
) (NamedResources[cidrSgIcmpRule], diag.Diagnostics) {
	var diags diag.Diagnostics
	newState := NewNamedResources[cidrSgIcmpRule]()
	var resp *protos.CidrSgIcmpRulesResp
	var err error
	if len(state.Items) > 0 {
		req := new(protos.FindCidrSgIcmpRulesReq)
		linq.From(state.Items).
			SelectT(func(i linq.KeyValue) string {
				return i.Value.(cidrSgIcmpRule).SgName.ValueString()
			}).
			Distinct().
			ToSlice(&req.Sg)
		if resp, err = client.FindCidrSgIcmpRules(ctx, req); err != nil {
			diags.AddError("read cidr-sg icmp rules", err.Error())
			return newState, diags
		}
	}

	for _, icmpRule := range resp.GetRules() { //nolint:dupl
		it := cidrSgIcmpRule{
			Traffic:   types.StringValue(strings.ToLower(icmpRule.GetTraffic().String())),
			Cidr:      types.StringValue(icmpRule.GetCIDR()),
			SgName:    types.StringValue(icmpRule.GetSG()),
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
				break
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
