package provider

import (
	"context"
	"fmt"

	protos "github.com/H-BF/protos/pkg/api/sgroups"
	sgAPI "github.com/H-BF/sgroups/internal/api/sgroups"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
)

type (
	SingleResource interface {
		ResourceAttributes() map[string]schema.Attribute
	}

	protoSubject interface {
		protos.SyncNetworks |
			protos.SyncSecurityGroups |
			protos.SyncSGRules |
			protos.SyncFqdnRules
	}

	Description struct {
		ResourceDescription string
		ItemsDescription    string
	}

	CollectionResource[T SingleResource, S protoSubject] struct {
		suffix      string
		description Description
		client      *sgAPI.Client
		toProto     func(map[string]T) *S
		read        func(ctx context.Context, model CollectionResourceModel[T, S], client *sgAPI.Client) (CollectionResourceModel[T, S], error)
		sr          SingleResource
	}
)

func (c *CollectionResource[T, S]) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + c.suffix
}

func (c *CollectionResource[T, S]) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: c.description.ResourceDescription,
		Attributes: map[string]schema.Attribute{
			"items": schema.MapNestedAttribute{
				Description: c.description.ItemsDescription,
				Required:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: c.sr.ResourceAttributes(),
				},
			},
		},
	}
}

func (c *CollectionResource[T, S]) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan CollectionResourceModel[T, S]

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Convert from Terraform data model into GRPC data model
	syncReq := plan.asSyncReq(protos.SyncReq_Upsert, c.toProto)

	// Send GRPC request
	if _, err := c.client.Sync(ctx, syncReq); err != nil {
		resp.Diagnostics.AddError(
			"Error creating resource",
			"Could not create resource: "+err.Error())
		return
	}

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (c *CollectionResource[T, S]) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state CollectionResourceModel[T, S]

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Create GRPC request and convert response to Terraform data model
	var err error
	if state, err = c.read(ctx, state, c.client); err != nil {
		resp.Diagnostics.AddError(
			"Error reading resource state",
			err.Error())
	}

	// Save updated data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (c *CollectionResource[T, S]) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state CollectionResourceModel[T, S]

	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	itemsToDelete := map[string]T{}
	for name, networkFeatures := range state.Items {
		if _, ok := plan.Items[name]; !ok {
			// if item is missing in plan state - delete it
			itemsToDelete[name] = networkFeatures
		}
	}

	if len(itemsToDelete) > 0 {
		tempModel := CollectionResourceModel[T, S]{
			Items: itemsToDelete,
		}
		delReq := tempModel.asSyncReq(protos.SyncReq_Delete, c.toProto)

		if _, err := c.client.Sync(ctx, delReq); err != nil {
			resp.Diagnostics.AddError(
				"Error updating resource",
				"Could not delete resource: "+err.Error())
			return
		}
	}

	updateReq := plan.asSyncReq(protos.SyncReq_Upsert, c.toProto)

	if _, err := c.client.Sync(ctx, updateReq); err != nil {
		resp.Diagnostics.AddError(
			"Error updating resource",
			"Could not update resource: "+err.Error())
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (c *CollectionResource[T, S]) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state CollectionResourceModel[T, S]

	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	delReq := state.asSyncReq(protos.SyncReq_Delete, c.toProto)

	if _, err := c.client.Sync(ctx, delReq); err != nil {
		resp.Diagnostics.AddError(
			"Error deleting networks",
			"Could not delete networks: "+err.Error())
		return
	}
}

func (c *CollectionResource[T, S]) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

	c.client = &client
}

var (
	_ resource.Resource              = &CollectionResource[networkItem, protos.SyncNetworks]{}
	_ resource.ResourceWithConfigure = &CollectionResource[networkItem, protos.SyncNetworks]{}
)
