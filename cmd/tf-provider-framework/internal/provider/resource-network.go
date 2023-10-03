package provider

import (
	"context"
	"fmt"
	"github.com/H-BF/protos/pkg/api/common"
	protos "github.com/H-BF/protos/pkg/api/sgroups"
	"github.com/H-BF/sgroups/cmd/tf-provider-framework/internal/validators"
	sgAPI "github.com/H-BF/sgroups/internal/api/sgroups"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func NewNetworkResource() resource.Resource {
	return &networkResource{}
}

var _ resource.Resource = &networkResource{}
var _ resource.ResourceWithConfigure = &networkResource{}

type networkResource struct {
	client sgAPI.Client
}

type networkResourceModel struct {
	Name types.String `tfsdk:"name"`
	Cidr types.String `tfsdk:"cidr"`
}

func (nr *networkResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_network"
}

func (nr *networkResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Single network resource",
		Attributes: map[string]schema.Attribute{
			"name": schema.StringAttribute{
				Required: true,
			},
			"cidr": schema.StringAttribute{
				Required: true,
				Validators: []validator.String{
					validators.IsCIDR(),
				},
			},
		},
	}
}

func (nr *networkResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(sgAPI.Client)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Data Source Configure Type",
			fmt.Sprintf("Expected *grpc.ClientConn, got: %T.", req.ProviderData),
		)

		return
	}

	nr.client = client
}

func (nr *networkResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan networkResourceModel

	// Read Terraform plan data into the model
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Convert from Terraform data model into GRPC data model
	var sn protos.SyncNetworks
	sn.Networks = append(sn.Networks, &protos.Network{
		Name:    plan.Name.ValueString(),
		Network: &common.Networks_NetIP{CIDR: plan.Cidr.ValueString()},
	})
	syncReq := protos.SyncReq{
		SyncOp: protos.SyncReq_Upsert,
		Subject: &protos.SyncReq_Networks{
			Networks: &sn,
		},
	}

	// Send GRPC request
	if _, err := nr.client.Sync(ctx, &syncReq); err != nil {
		resp.Diagnostics.AddError(
			"Error creating network",
			"Could not create network: "+err.Error())
		return
	}

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (nr *networkResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state networkResourceModel

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Convert from Terraform data model into GRPC data model
	listReq := protos.ListNetworksReq{
		NeteworkNames: []string{state.Name.ValueString()},
	}

	// Create GRPC request
	listResp, err := nr.client.ListNetworks(ctx, &listReq)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error reading network state",
			"Could not perform ListNetworks GRPC call: "+err.Error(),
		)
		return
	}

	// Convert from the GRPC data model to the Terraform data model
	// and refresh any attribute values.
	if srcNetworks := listResp.GetNetworks(); len(srcNetworks) > 0 {
		nw := srcNetworks[0]
		state.Name = types.StringValue(nw.GetName())
		state.Cidr = types.StringValue(nw.GetNetwork().GetCIDR())
	} else {
		resp.Diagnostics.AddError(
			"Error reading network state",
			fmt.Sprintf("Network with name %s doesn't exist", state.Name.ValueString()))
	}

	// Save updated data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (nr *networkResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	//TODO implement me
	panic("implement me")
}

func (nr *networkResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	//TODO implement me
	panic("implement me")
}