package provider

import (
	"context"

	protos "github.com/H-BF/protos/pkg/api/sgroups"
	sgAPI "github.com/H-BF/sgroups/internal/api/sgroups"

	"github.com/ahmetb/go-linq/v3"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
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
		suffix:       "_groups",
		description:  d,
		toSubjOfSync: sgs2SyncSubj,
		read:         readSgs,
	}
}

type (
	sgsResource = CollectionResource[sgItem, protos.SyncSecurityGroups]

	sgsResourceModel = CollectionResourceModel[sgItem, protos.SyncSecurityGroups]

	sgItem struct {
		Name          types.String `tfsdk:"name"`
		Logs          types.Bool   `tfsdk:"logs"`
		Trace         types.Bool   `tfsdk:"trace"`
		DefaultAction types.String `tfsdk:"default_action"`
		Networks      types.Set    `tfsdk:"networks"`
	}
)

func (item sgItem) ResourceAttributes() map[string]schema.Attribute {
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
	}
}

func (item sgItem) IsDiffer(oldSg sgItem) bool {
	return !(item.Name.Equal(oldSg.Name) &&
		item.Logs.Equal(oldSg.Logs) &&
		item.Trace.Equal(oldSg.Trace) &&
		item.DefaultAction.Equal(oldSg.DefaultAction) &&
		item.Networks.Equal(oldSg.Networks))
}

func sgs2SyncSubj(
	ctx context.Context, items map[string]sgItem,
) (*protos.SyncSecurityGroups, diag.Diagnostics) {
	var syncGroups protos.SyncSecurityGroups
	var diags diag.Diagnostics
	for _, sgFeatures := range items {
		da := sgFeatures.DefaultAction.ValueString()
		var networks []string
		diags.Append(sgFeatures.Networks.ElementsAs(ctx, &networks, true)...)
		if diags.HasError() {
			return nil, diags
		}
		syncGroups.Groups = append(syncGroups.Groups, &protos.SecGroup{
			Name:          sgFeatures.Name.ValueString(),
			Networks:      networks,
			DefaultAction: protos.SecGroup_DefaultAction(protos.SecGroup_DefaultAction_value[da]),
			Trace:         sgFeatures.Trace.ValueBool(),
			Logs:          sgFeatures.Logs.ValueBool(),
		})
	}
	return &syncGroups, diags
}

func readSgs(ctx context.Context, state sgsResourceModel, client *sgAPI.Client) (sgsResourceModel, diag.Diagnostics) {
	var (
		diags    diag.Diagnostics
		err      error
		listResp *protos.ListSecurityGroupsResp
	)
	newState := sgsResourceModel{Items: make(map[string]sgItem)}
	if len(state.Items) > 0 {
		var listReq protos.ListSecurityGroupsReq
		linq.From(state.Items).
			Select(func(i interface{}) interface{} {
				return i.(linq.KeyValue).Value.(sgItem).Name.ValueString()
			}).Distinct().ToSlice(&listReq.SgNames)
		listResp, err = client.ListSecurityGroups(ctx, &listReq)
		if err != nil {
			diags.AddError("reading SG state", err.Error())
			return sgsResourceModel{}, diags
		}
	}

	for _, sg := range listResp.GetGroups() {
		if sg != nil {
			networks, d := types.SetValueFrom(ctx, types.StringType, sg.GetNetworks())
			diags.Append(d...)
			if d.HasError() {
				return sgsResourceModel{}, diags
			}
			if _, ok := state.Items[sg.GetName()]; ok {
				newState.Items[sg.GetName()] = sgItem{
					Name:          types.StringValue(sg.GetName()),
					Logs:          types.BoolValue(sg.GetLogs()),
					Trace:         types.BoolValue(sg.GetTrace()),
					DefaultAction: types.StringValue(sg.GetDefaultAction().String()),
					Networks:      networks,
				}
			}
		}
	}
	return newState, diags
}
