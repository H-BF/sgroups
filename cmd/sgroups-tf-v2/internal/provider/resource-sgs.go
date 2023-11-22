package provider

import (
	"context"

	sgAPI "github.com/H-BF/sgroups/internal/api/sgroups"
	"github.com/H-BF/sgroups/internal/dict"
	model "github.com/H-BF/sgroups/internal/models/sgroups"

	"github.com/H-BF/protos/pkg/api/common"
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
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
)

func NewSgsResource() resource.Resource {
	d := Description{
		ResourceDescription: "mapped 'Name' -> 'Security Group' resource",
		ItemsDescription:    "Security Groups",
	}
	return &sgsResource{
		suffix:        "_groups",
		description:   d,
		toSubjOfSync:  sgs2SyncSubj,
		hookUpdateReq: removeIcmpRules,
		read:          readSgs,
	}
}

type (
	securityGroupSubject struct {
		syncGroups     *protos.SyncSecurityGroups
		syncIcmpParams *protos.SyncSgIcmpRules
	}

	sgsResource = CollectionResource[sgItem, securityGroupSubject]

	sgsResourceModel = CollectionResourceModel[sgItem, securityGroupSubject]

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

func (item sgItem) ResourceAttributes() map[string]schema.Attribute {
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
					protos.SecGroup_ACCEPT.String(),
					protos.SecGroup_DROP.String(),
					protos.SecGroup_DEFAULT.String()),
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
			Attributes:  icmpParams.ResourceAttributes(),
			Default:     objectdefault.StaticValue(icmpParams.nullObj()),
		},
		"icmp6": schema.SingleNestedAttribute{
			Description: "ICMP6 parameters for security group",
			Optional:    true,
			Computed:    true,
			Attributes:  icmpParams.ResourceAttributes(),
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

func (item sgItem) icmpObj2Proto(ctx context.Context, version common.IpAddrFamily) (*protos.SgIcmpRule, diag.Diagnostics) {
	var (
		icmpParams IcmpParameters
		diags      diag.Diagnostics
	)
	switch version {
	case common.IpAddrFamily_IPv4:
		diags.Append(item.Icmp.As(ctx, &icmpParams, basetypes.ObjectAsOptions{UnhandledUnknownAsEmpty: true})...)
	case common.IpAddrFamily_IPv6:
		diags.Append(item.Icmp6.As(ctx, &icmpParams, basetypes.ObjectAsOptions{UnhandledUnknownAsEmpty: true})...)
	default:
		panic("unexpected `version` value")
	}
	if diags.HasError() {
		return nil, diags
	}
	protoRule := &protos.SgIcmpRule{
		Sg:    item.Name.ValueString(),
		ICMP:  &common.ICMP{IPv: version},
		Logs:  icmpParams.Logs.ValueBool(),
		Trace: icmpParams.Trace.ValueBool(),
	}
	diags.Append(icmpParams.Type.ElementsAs(ctx, &protoRule.ICMP.Types, true)...)
	if diags.HasError() {
		return nil, diags
	}
	return protoRule, nil
}

func sgs2SyncSubj(
	ctx context.Context, items map[string]sgItem,
) (*securityGroupSubject, diag.Diagnostics) {
	syncSubject := securityGroupSubject{
		syncGroups:     &protos.SyncSecurityGroups{},
		syncIcmpParams: &protos.SyncSgIcmpRules{},
	}
	var diags diag.Diagnostics
	for _, sgFeatures := range items {
		da := sgFeatures.DefaultAction.ValueString()
		var networks []string
		diags.Append(sgFeatures.Networks.ElementsAs(ctx, &networks, true)...)
		if diags.HasError() {
			return nil, diags
		}
		syncSubject.syncGroups.Groups = append(syncSubject.syncGroups.Groups, &protos.SecGroup{
			Name:          sgFeatures.Name.ValueString(),
			Networks:      networks,
			DefaultAction: protos.SecGroup_DefaultAction(protos.SecGroup_DefaultAction_value[da]),
			Trace:         sgFeatures.Trace.ValueBool(),
			Logs:          sgFeatures.Logs.ValueBool(),
		})

		if !sgFeatures.Icmp.IsNull() {
			protoRule, d := sgFeatures.icmpObj2Proto(ctx, common.IpAddrFamily_IPv4)
			diags.Append(d...)
			if diags.HasError() {
				return nil, diags
			}
			syncSubject.syncIcmpParams.Rules = append(syncSubject.syncIcmpParams.Rules, protoRule)
		}

		if !sgFeatures.Icmp6.IsNull() {
			protoRule, d := sgFeatures.icmpObj2Proto(ctx, common.IpAddrFamily_IPv6)
			diags.Append(d...)
			if diags.HasError() {
				return nil, diags
			}
			syncSubject.syncIcmpParams.Rules = append(syncSubject.syncIcmpParams.Rules, protoRule)
		}
	}

	return &syncSubject, diags
}

func readSgs(ctx context.Context, state sgsResourceModel, client *sgAPI.Client) (sgsResourceModel, diag.Diagnostics) {
	var (
		diags          diag.Diagnostics
		err            error
		listGroupsResp *protos.ListSecurityGroupsResp
		sgIcmpResp     *protos.SgIcmpRulesResp
		id2Icmp        dict.HDict[model.SgIcmpRuleID, *protos.SgIcmpRule]
		icmpParams     IcmpParameters
	)
	newState := sgsResourceModel{Items: make(map[string]sgItem)}
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
			Sg: listGroupsReq.SgNames,
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
			return sgsResourceModel{}, diags
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
					return sgsResourceModel{}, diags
				}
				newItem.Icmp = icmpValue
			}

			//check for icmp6 rule
			id.IPv = 6
			if icmp, ok := id2Icmp.Get(id); ok {
				icmpValue, d := icmpParams.fromProto(ctx, icmp)
				diags.Append(d...)
				if diags.HasError() {
					return sgsResourceModel{}, diags
				}
				newItem.Icmp6 = icmpValue
			}

			newState.Items[sg.GetName()] = newItem
		}
	}
	return newState, diags
}

func removeIcmpRules(ctx context.Context, stateItems map[string]sgItem, planItems map[string]sgItem) (*protos.SyncReq, diag.Diagnostics) {
	var (
		rules = &protos.SyncSgIcmpRules{}
		diags diag.Diagnostics
	)

	for key, planItem := range planItems {
		if stateItem, ok := stateItems[key]; ok {
			if isIcmpRemoved(stateItem.Icmp, planItem.Icmp) {
				protoRule, d := stateItem.icmpObj2Proto(ctx, common.IpAddrFamily_IPv4)
				diags.Append(d...)
				if diags.HasError() {
					return nil, diags
				}
				rules.Rules = append(rules.Rules, protoRule)
			}

			if isIcmpRemoved(stateItem.Icmp6, planItem.Icmp6) {
				protoRule, d := stateItem.icmpObj2Proto(ctx, common.IpAddrFamily_IPv6)
				diags.Append(d...)
				if diags.HasError() {
					return nil, diags
				}
				rules.Rules = append(rules.Rules, protoRule)
			}
		}
	}

	return &protos.SyncReq{
		SyncOp:  protos.SyncReq_Delete,
		Subject: &protos.SyncReq_SgIcmpRules{SgIcmpRules: rules},
	}, diags
}

func isIcmpRemoved(stateIcmp types.Object, planIcmp types.Object) bool {
	return !stateIcmp.IsNull() && planIcmp.IsNull()
}
