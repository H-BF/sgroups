package provider

import (
	"context"
	"fmt"
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
	"golang.org/x/exp/maps"
)

func NewSgsResource() resource.Resource {
	return &sgsResource{}
}

var (
	_ resource.ResourceWithConfigure = &sgsResource{}
)

type (
	sgsResource struct {
		client sgAPI.Client
	}

	sgsResourceModel struct {
		Items map[string]sgItem `tfsdk:"items"`
	}

	sgItem struct {
		Logs          types.Bool   `tfsdk:"logs"`
		Trace         types.Bool   `tfsdk:"trace"`
		DefaultAction types.String `tfsdk:"default_action"`
		Networks      types.String `tfsdk:"networks"`
	}
)

func (r *sgsResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_groups"
}

func (r *sgsResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Collection of security groups",
		Attributes: map[string]schema.Attribute{
			"items": schema.MapNestedAttribute{
				Description: "Mapping from SG name to it features",
				Required:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
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
					},
				},
			},
		},
	}
}

func (r *sgsResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan sgsResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	syncReq := plan.asSyncReq(protos.SyncReq_Upsert)

	if _, err := r.client.Sync(ctx, &syncReq); err != nil {
		resp.Diagnostics.AddError(
			"Error creating security groups",
			"Could not create security groups: "+err.Error())
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *sgsResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state sgsResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	listReq := state.asReadReq()

	listResp, err := r.client.ListSecurityGroups(ctx, &listReq)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error reading security groups state",
			"Could not perform ListSecurityGroups GRPC call: "+err.Error(),
		)
		return
	}

	if g := listResp.GetGroups(); len(g) == 0 {
		resp.Diagnostics.AddError(
			"Error reading security groups state",
			fmt.Sprintf("Resource doesn't contain at least one of theese security groups: %s",
				strings.Join(maps.Keys(state.Items), ", ")))
		return
	}

	if err := state.loadFromProto(listResp); err != nil {
		resp.Diagnostics.AddError(
			"Error reading security groups state",
			"Could not convert ListSecurityGroups response into new state: "+err.Error())
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *sgsResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state sgsResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	itemsToDelete := map[string]sgItem{}
	for name, sgFeatures := range state.Items {
		if _, ok := plan.Items[name]; !ok {
			itemsToDelete[name] = sgFeatures
		}
	}

	if len(itemsToDelete) > 0 {
		tempModel := sgsResourceModel{
			Items: itemsToDelete,
		}
		delReq := tempModel.asSyncReq(protos.SyncReq_Delete)

		if _, err := r.client.Sync(ctx, &delReq); err != nil {
			resp.Diagnostics.AddError(
				"Error updating security groups",
				"Could not delete security groups: "+err.Error())
			return
		}
	}

	updateReq := plan.asSyncReq(protos.SyncReq_Upsert)

	if _, err := r.client.Sync(ctx, &updateReq); err != nil {
		resp.Diagnostics.AddError(
			"Error updating security groups",
			"Could not update security groups: "+err.Error())
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *sgsResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state sgsResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	delReq := state.asSyncReq(protos.SyncReq_Delete)

	if _, err := r.client.Sync(ctx, &delReq); err != nil {
		resp.Diagnostics.AddError(
			"Error deleting security groups",
			"Could not delete security groups: "+err.Error())
		return
	}
}

func (r *sgsResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(sgAPI.Client)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Data Source Configure Type",
			fmt.Sprintf("Expected sgroups GRPC client, got: %T.", req.ProviderData),
		)

		return
	}

	r.client = client
}

func (model *sgsResourceModel) asSyncReq(operation protos.SyncReq_SyncOp) protos.SyncReq {
	var syncGroups protos.SyncSecurityGroups
	for name, sgFeatures := range model.Items {
		da := sgFeatures.DefaultAction.ValueString()
		syncGroups.Groups = append(syncGroups.Groups, &protos.SecGroup{
			Name:          name,
			Networks:      splitNetNames(sgFeatures.Networks.ValueString()),
			DefaultAction: protos.SecGroup_DefaultAction(protos.SecGroup_DefaultAction_value[da]),
			Trace:         sgFeatures.Trace.ValueBool(),
			Logs:          sgFeatures.Logs.ValueBool(),
		})
	}
	return protos.SyncReq{
		SyncOp: operation,
		Subject: &protos.SyncReq_Groups{
			Groups: &syncGroups,
		},
	}
}

func (model *sgsResourceModel) asReadReq() protos.ListSecurityGroupsReq {
	return protos.ListSecurityGroupsReq{
		SgNames: maps.Keys(model.Items),
	}
}

func (model *sgsResourceModel) loadFromProto(resp *protos.ListSecurityGroupsResp) error {
	newItems := make(map[string]sgItem, len(model.Items))
	for _, sg := range resp.GetGroups() {
		if sg != nil {
			newItems[sg.GetName()] = sgItem{
				Logs:          types.BoolValue(sg.GetLogs()),
				Trace:         types.BoolValue(sg.GetTrace()),
				DefaultAction: types.StringValue(sg.GetDefaultAction().String()),
				Networks:      types.StringValue(strings.Join(sg.GetNetworks(), ",")),
			}
		}
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
