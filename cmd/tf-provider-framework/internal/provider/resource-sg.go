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
)

func NewSgResource() resource.Resource {
	return &sgResource{}
}

var (
	_ resource.ResourceWithConfigure = &sgResource{}
)

type (
	sgResource struct {
		client sgAPI.Client
	}

	sgResourceModel struct {
		Name          types.String `tfsdk:"name"`
		Logs          types.Bool   `tfsdk:"logs"`
		Trace         types.Bool   `tfsdk:"trace"`
		DefaultAction types.String `tfsdk:"default_action"`
		Networks      types.String `tfsdk:"networks"`
	}
)

func (r *sgResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_group"
}

func (r *sgResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Single security group resource",
		Attributes: map[string]schema.Attribute{
			"name": schema.StringAttribute{
				Description: "Security group name",
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
			"networks": schema.StringAttribute{
				Description: "Set of networks for security group",
				Optional:    true,
				PlanModifiers: []planmodifier.String{
					planmodifiers.CommaSeparatedSet("networks are same", splitNetNames),
				},
			},
		},
	}
}

func (r *sgResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan sgResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	syncReq := reqFromSgResource(plan, protos.SyncReq_Upsert)

	if _, err := r.client.Sync(ctx, &syncReq); err != nil {
		resp.Diagnostics.AddError(
			"Error creating security group",
			"Could not create security group: "+err.Error())
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *sgResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state sgResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	listReq := protos.ListSecurityGroupsReq{
		SgNames: []string{state.Name.ValueString()},
	}

	listResp, err := r.client.ListSecurityGroups(ctx, &listReq)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error reading security group state",
			"Could not perform ListSecurityGroups GRPC call: "+err.Error(),
		)
		return
	}

	if g := listResp.GetGroups(); len(g) > 0 {
		sg := g[0]
		if state.Name.ValueString() != sg.GetName() {
			resp.Diagnostics.AddError(
				"Error reading security group state",
				"ListSecurityGroups returned wrong name: "+sg.GetName())
			return
		}
		state.Logs = types.BoolValue(sg.GetLogs())
		state.Trace = types.BoolValue(sg.GetTrace())
		state.DefaultAction = types.StringValue(sg.GetDefaultAction().String())
		state.Networks = types.StringValue(strings.Join(sg.GetNetworks(), ","))
	} else {
		resp.Diagnostics.AddError(
			"Error reading security group state",
			fmt.Sprintf("Security group with name %s doesn't exist", state.Name.ValueString()))
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *sgResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state sgResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.Plan.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if !plan.Name.Equal(state.Name) {
		resp.Diagnostics.AddError(
			"Error updating security group",
			"Unable change security group name")
		return
	}

	syncReq := reqFromSgResource(plan, protos.SyncReq_Upsert)

	if _, err := r.client.Sync(ctx, &syncReq); err != nil {
		resp.Diagnostics.AddError(
			"Error updating security group",
			"Could not update security group: "+err.Error())
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *sgResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state sgResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	delReq := reqFromSgResource(state, protos.SyncReq_Delete)

	if _, err := r.client.Sync(ctx, &delReq); err != nil {
		resp.Diagnostics.AddError(
			"Error deleting security group",
			"Could not delete security group: "+err.Error())
		return
	}
}

func (r *sgResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func reqFromSgResource(model sgResourceModel, operation protos.SyncReq_SyncOp) protos.SyncReq {
	sg := protos.SecGroup{
		Name:          model.Name.ValueString(),
		Networks:      splitNetNames(model.Networks.ValueString()),
		DefaultAction: protos.SecGroup_DefaultAction(protos.SecGroup_DefaultAction_value[model.DefaultAction.ValueString()]),
		Trace:         model.Trace.ValueBool(),
		Logs:          model.Logs.ValueBool(),
	}
	return protos.SyncReq{
		SyncOp: operation,
		Subject: &protos.SyncReq_Groups{
			Groups: &protos.SyncSecurityGroups{
				Groups: []*protos.SecGroup{&sg},
			},
		},
	}
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
