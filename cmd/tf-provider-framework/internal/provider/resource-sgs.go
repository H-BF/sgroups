package provider

import (
	"context"

	protos "github.com/H-BF/protos/pkg/api/sgroups"
	sgAPI "github.com/H-BF/sgroups/internal/api/sgroups"

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
		ResourceDescription: "Collection of security groups",
		ItemsDescription:    "Mapping from SG name to it features",
	}
	return &sgsResource{
		suffix:      "_groups",
		description: d,
		toProto:     sgsToProto,
		read:        listSgs,
		sr:          sgItem{},
	}
}

type (
	sgsResource = CollectionResource[sgItem, protos.SyncSecurityGroups]

	sgsResourceModel = CollectionResourceModel[sgItem, protos.SyncSecurityGroups]

	sgItem struct {
		Logs          types.Bool   `tfsdk:"logs"`
		Trace         types.Bool   `tfsdk:"trace"`
		DefaultAction types.String `tfsdk:"default_action"`
		Networks      types.Set    `tfsdk:"networks"`
	}
)

func (item sgItem) ResourceAttributes() map[string]schema.Attribute {
	return map[string]schema.Attribute{
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

func sgsToProto(
	ctx context.Context, items map[string]sgItem,
) (*protos.SyncSecurityGroups, diag.Diagnostics) {
	syncGroups := &protos.SyncSecurityGroups{}
	var diags diag.Diagnostics
	for name, sgFeatures := range items {
		da := sgFeatures.DefaultAction.ValueString()
		var networks []string
		diags.Append(sgFeatures.Networks.ElementsAs(ctx, &networks, true)...)
		if diags.HasError() {
			return nil, diags
		}
		syncGroups.Groups = append(syncGroups.Groups, &protos.SecGroup{
			Name:          name,
			Networks:      networks,
			DefaultAction: protos.SecGroup_DefaultAction(protos.SecGroup_DefaultAction_value[da]),
			Trace:         sgFeatures.Trace.ValueBool(),
			Logs:          sgFeatures.Logs.ValueBool(),
		})
	}
	return syncGroups, diags
}

func listSgs(ctx context.Context, state sgsResourceModel, client *sgAPI.Client) (sgsResourceModel, diag.Diagnostics) {
	var diags diag.Diagnostics
	listReq := protos.ListSecurityGroupsReq{
		SgNames: state.getNames(),
	}

	listResp, err := client.ListSecurityGroups(ctx, &listReq)
	if err != nil {
		diags.AddError("Error reading resource state",
			"Could not perform ListSecurityGroups GRPC call: "+err.Error())
		return sgsResourceModel{}, diags
	}

	newItems := make(map[string]sgItem, len(state.Items))
	for _, sg := range listResp.GetGroups() {
		if sg != nil {
			networks, d := types.SetValueFrom(ctx, types.StringType, sg.GetNetworks())
			diags.Append(d...)
			newItems[sg.GetName()] = sgItem{
				Logs:          types.BoolValue(sg.GetLogs()),
				Trace:         types.BoolValue(sg.GetTrace()),
				DefaultAction: types.StringValue(sg.GetDefaultAction().String()),
				Networks:      networks,
			}
		}
	}
	state.Items = newItems
	return state, diags
}
