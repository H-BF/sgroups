package provider

import (
	"context"

	sgAPI "github.com/H-BF/sgroups/v2/internal/api/sgroups"
	model "github.com/H-BF/sgroups/v2/internal/domains/sgroups"

	"github.com/H-BF/corlib/pkg/dict"
	protos "github.com/H-BF/protos/pkg/api/sgroups"
	"github.com/ahmetb/go-linq/v3"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/objectdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func NewSgsResource() resource.Resource {
	d := Description{
		ResourceDescription: "mapped 'Name' -> 'Security Group' resource",
		ItemsDescription:    "Security Groups",
	}
	return &sgsResource{
		suffix:      "_groups",
		description: d,
		readState:   readSgState,
	}
}

type (
	sgsResource = CollectionResource[sgItem, tfSg2Backend]

	sgItem struct {
		Name          types.String `tfsdk:"name"`
		Logs          types.Bool   `tfsdk:"logs"`
		Trace         types.Bool   `tfsdk:"trace"`
		DefaultAction types.String `tfsdk:"default_action"`
		Networks      types.Set    `tfsdk:"networks"`
		Icmp          types.Object `tfsdk:"icmp"`
		Icmp6         types.Object `tfsdk:"icmp6"`
	}
)

func (item sgItem) Attributes() map[string]schema.Attribute {
	icmpParams := IcmpParameters{}
	return map[string]schema.Attribute{
		"name": schema.StringAttribute{
			Description: "security group name",
			Required:    true,
		},
		"logs": schema.BoolAttribute{
			Description: "Enables logs on security group",
			Optional:    true,
			Computed:    true,
			Default:     booldefault.StaticBool(false),
		},
		"trace": schema.BoolAttribute{
			Description: "Enables traces on security group",
			Optional:    true,
			Computed:    true,
			Default:     booldefault.StaticBool(false),
		},
		"default_action": schema.StringAttribute{
			Description: "Default action on security group",
			Optional:    true,
			Computed:    true,
			Default:     stringdefault.StaticString(protos.SecGroup_DROP.String()),
			Validators: []validator.String{
				stringvalidator.OneOf(
					protos.SecGroup_DROP.String(),
					protos.SecGroup_ACCEPT.String()),
			},
		},
		"networks": schema.SetAttribute{
			Description: "Set of networks for security group",
			Optional:    true,
			ElementType: types.StringType,
		},
		"icmp": schema.SingleNestedAttribute{
			Description: "ICMP parameters for security group",
			Optional:    true,
			Computed:    true,
			Attributes:  icmpParams.Attributes(),
			Default:     objectdefault.StaticValue(icmpParams.nullObj()),
		},
		"icmp6": schema.SingleNestedAttribute{
			Description: "ICMP6 parameters for security group",
			Optional:    true,
			Computed:    true,
			Attributes:  icmpParams.Attributes(),
			Default:     objectdefault.StaticValue(icmpParams.nullObj()),
		},
	}
}

func (item sgItem) IsDiffer(ctx context.Context, other sgItem) bool {
	return !(item.Name.Equal(other.Name) &&
		item.Logs.Equal(other.Logs) &&
		item.Trace.Equal(other.Trace) &&
		item.DefaultAction.Equal(other.DefaultAction) &&
		item.Networks.Equal(other.Networks) &&
		item.Icmp.Equal(other.Icmp) &&
		item.Icmp6.Equal(other.Icmp6))
}

func readSgState(ctx context.Context, state NamedResources[sgItem], client *sgAPI.Client) (NamedResources[sgItem], diag.Diagnostics) {
	var (
		diags          diag.Diagnostics
		err            error
		listGroupsResp *protos.ListSecurityGroupsResp
		sgIcmpResp     *protos.SgIcmpRulesResp
		id2Icmp        dict.HDict[model.SgIcmpRuleID, *protos.SgIcmpRule]
		icmpParams     IcmpParameters
	)
	newState := NewNamedResources[sgItem]()
	if len(state.Items) > 0 {
		var listGroupsReq protos.ListSecurityGroupsReq
		linq.From(state.Items).
			Select(func(i interface{}) interface{} {
				return i.(linq.KeyValue).Value.(sgItem).Name.ValueString()
			}).Distinct().ToSlice(&listGroupsReq.SgNames)

		listGroupsResp, err = client.ListSecurityGroups(ctx, &listGroupsReq)
		if err != nil {
			diags.AddError("read security groups", err.Error())
			return newState, diags
		}

		sgIcmpReq := protos.FindSgIcmpRulesReq{
			SG: listGroupsReq.SgNames,
		}
		if sgIcmpResp, err = client.FindSgIcmpRules(ctx, &sgIcmpReq); err != nil {
			diags.AddError("read security groups", err.Error())
			return newState, diags
		}
	}

	for _, icmpRule := range sgIcmpResp.GetRules() {
		var rule model.SgIcmpRule
		if rule, err = sgAPI.Proto2MOdelSgIcmpRule(icmpRule); err != nil {
			diags.AddError("read security groups", err.Error())
			return newState, diags
		}
		id2Icmp.Insert(rule.ID(), icmpRule)
	}

	for _, sg := range listGroupsResp.GetGroups() {
		networks, d := types.SetValueFrom(ctx, types.StringType, sg.GetNetworks())
		diags.Append(d...)
		if d.HasError() {
			return NamedResources[sgItem]{}, diags
		}
		if _, ok := state.Items[sg.GetName()]; ok {
			newItem := sgItem{
				Name:          types.StringValue(sg.GetName()),
				Logs:          types.BoolValue(sg.GetLogs()),
				Trace:         types.BoolValue(sg.GetTrace()),
				DefaultAction: types.StringValue(sg.GetDefaultAction().String()),
				Networks:      networks,
				Icmp:          icmpParams.nullObj(),
				Icmp6:         icmpParams.nullObj(),
			}

			// check for icmp4 rule
			id := model.SgIcmpRuleID{IPv: 4, Sg: sg.GetName()}
			if icmp, ok := id2Icmp.Get(id); ok {
				icmpValue, d := icmpParams.fromProto(ctx, icmp)
				diags.Append(d...)
				if diags.HasError() {
					return NamedResources[sgItem]{}, diags
				}
				newItem.Icmp = icmpValue
			}

			//check for icmp6 rule
			id.IPv = 6
			if icmp, ok := id2Icmp.Get(id); ok {
				icmpValue, d := icmpParams.fromProto(ctx, icmp)
				diags.Append(d...)
				if diags.HasError() {
					return NamedResources[sgItem]{}, diags
				}
				newItem.Icmp6 = icmpValue
			}

			newState.Items[sg.GetName()] = newItem
		}
	}
	return newState, diags
}
