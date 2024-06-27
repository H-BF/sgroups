package provider

import (
	"context"
	"fmt"

	protos "github.com/H-BF/protos/pkg/api/sgroups"
	sgAPI "github.com/H-BF/sgroups/internal/api/sgroups"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
)

type (
	SingleResource[T any] interface {
		Attributes() map[string]schema.Attribute
		IsDiffer(context.Context, T) bool
	}

	Description struct {
		ResourceDescription string
		ItemsDescription    string
	}

	CollectionResource[T SingleResource[T], S tf2backend[T]] struct {
		suffix      string
		description Description
		client      *sgAPI.Client
		readState   func(context.Context, NamedResources[T], *sgAPI.Client) (NamedResources[T], diag.Diagnostics)
	}
)

func (c *CollectionResource[T, S]) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + c.suffix
}

func (c *CollectionResource[T, S]) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	var sr T
	resp.Schema = schema.Schema{
		Description: c.description.ResourceDescription,
		Attributes: map[string]schema.Attribute{
			"items": schema.MapNestedAttribute{
				Description: c.description.ItemsDescription,
				Required:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: sr.Attributes(),
				},
			},
		},
	}
}

func (c *CollectionResource[T, S]) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan NamedResources[T]

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	var syncer S
	if di := syncer.sync(ctx, plan, c.client, protos.SyncReq_Upsert); di.HasError() {
		resp.Diagnostics.Append(di...)
		return
	}
	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (c *CollectionResource[T, S]) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state NamedResources[T]

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Create GRPC request and convert response to Terraform data model
	var diags diag.Diagnostics
	if state, diags = c.readState(ctx, state, c.client); diags.HasError() {
		for _, diagError := range diags.Errors() {
			resp.Diagnostics.AddError(
				"read "+c.description.ItemsDescription,
				diagError.Summary()+":"+diagError.Detail())
		}
	}

	// Save updated data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (c *CollectionResource[T, S]) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state NamedResources[T]

	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	itemsToDelete := NewNamedResources[T]()
	for name, itemFeatures := range state.Items {
		if _, ok := plan.Items[name]; !ok {
			// if item is missing in plan state - delete it
			itemsToDelete.Items[name] = itemFeatures
		}
	}
	if len(itemsToDelete.Items) > 0 {
		var syncer S
		if di := syncer.sync(ctx, itemsToDelete, c.client, protos.SyncReq_Delete); di.HasError() {
			resp.Diagnostics.Append(di...)
			return
		}
	}

	itemsToUpdate := NewNamedResources[T]()
	for name, itemFeatures := range plan.Items {
		// in plan state can have unchanged items which should be ignored
		// missing items before and changed items should be updated
		if oldItemFeatures, ok := state.Items[name]; !ok || itemFeatures.IsDiffer(ctx, oldItemFeatures) {
			itemsToUpdate.Items[name] = itemFeatures
		}
	}
	if len(itemsToUpdate.Items) > 0 {
		var syncer S
		if di := syncer.sync(ctx, itemsToUpdate, c.client, protos.SyncReq_Upsert); di.HasError() {
			resp.Diagnostics.Append(di...)
			return
		}
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (c *CollectionResource[T, S]) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state NamedResources[T]
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	var syncer S
	if di := syncer.sync(ctx, state, c.client, protos.SyncReq_Delete); di.HasError() {
		resp.Diagnostics.Append(di...)
	}
}

func (c *CollectionResource[T, S]) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(sgAPI.Client)
	if !ok {
		resp.Diagnostics.AddError(
			"unexpected Data Source type",
			fmt.Sprintf("Expected sgroups client but got: %T.", req.ProviderData),
		)
		return
	}
	c.client = &client
}
