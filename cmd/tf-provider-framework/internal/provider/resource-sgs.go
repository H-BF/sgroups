package provider

import (
	"context"
	"sort"
	"strings"

	"github.com/H-BF/corlib/pkg/slice"
	protos "github.com/H-BF/protos/pkg/api/sgroups"
	"github.com/H-BF/sgroups/cmd/tf-provider-framework/internal/provider/planmodifiers"
	sgAPI "github.com/H-BF/sgroups/internal/api/sgroups"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
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
		Networks      types.String `tfsdk:"networks"`
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
		"networks": schema.StringAttribute{
			Description: "Set of networks for security group",
			Optional:    true,
			PlanModifiers: []planmodifier.String{
				planmodifiers.CommaSeparatedSet("networks are same", splitNetNames),
			},
		},
	}
}

func sgsToProto(items map[string]sgItem) *protos.SyncSecurityGroups {
	syncGroups := &protos.SyncSecurityGroups{}
	for name, sgFeatures := range items {
		da := sgFeatures.DefaultAction.ValueString()
		syncGroups.Groups = append(syncGroups.Groups, &protos.SecGroup{
			Name:          name,
			Networks:      splitNetNames(sgFeatures.Networks.ValueString()),
			DefaultAction: protos.SecGroup_DefaultAction(protos.SecGroup_DefaultAction_value[da]),
			Trace:         sgFeatures.Trace.ValueBool(),
			Logs:          sgFeatures.Logs.ValueBool(),
		})
	}
	return syncGroups
}

func listSgs(ctx context.Context, state sgsResourceModel, client *sgAPI.Client) (sgsResourceModel, error) {
	listReq := protos.ListSecurityGroupsReq{
		SgNames: state.getNames(),
	}

	listResp, err := client.ListSecurityGroups(ctx, &listReq)
	if err != nil {
		return sgsResourceModel{}, errGRPCCall
	}

	if g := listResp.GetGroups(); len(g) == 0 {
		return sgsResourceModel{}, errNotEnoughItems
	}

	newItems := make(map[string]sgItem, len(state.Items))
	for _, sg := range listResp.GetGroups() {
		if sg != nil {
			newItems[sg.GetName()] = sgItem{
				Logs:          types.BoolValue(sg.GetLogs()),
				Trace:         types.BoolValue(sg.GetTrace()),
				DefaultAction: types.StringValue(sg.GetDefaultAction().String()),
				Networks:      types.StringValue(strings.Join(sg.GetNetworks(), ",")),
			}
		}
	}
	return state, nil
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
