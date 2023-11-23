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
	/*//
	// KeyOps -
	KeyOps[T any] interface {
		String() string
		FromString(string) error
	}
	*/

	SingleResource[T any] interface {
		ResourceAttributes() map[string]schema.Attribute
		IsDiffer(context.Context, T) bool
	}

	subjectOfSync interface {
		securityGroupSubject |
			protos.SyncNetworks |
			protos.SyncSGRules |
			protos.SyncFqdnRules |
			protos.SyncSgSgIcmpRules
	}

	Description struct {
		ResourceDescription string
		ItemsDescription    string
	}

	CollectionResource[T SingleResource[T], S subjectOfSync] struct {
		suffix       string
		description  Description
		client       *sgAPI.Client
		toSubjOfSync func(context.Context, map[string]T) (*S, diag.Diagnostics)
		read         func(context.Context, CollectionResourceModel[T, S], *sgAPI.Client) (CollectionResourceModel[T, S], diag.Diagnostics)
		deleteReqs   func(ctx context.Context, stateItems map[string]T, planItems map[string]T) ([]*protos.SyncReq, diag.Diagnostics)
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
					Attributes: sr.ResourceAttributes(),
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
	syncReqs, diags := plan.toSyncReq(ctx, protos.SyncReq_Upsert, c.toSubjOfSync)
	if diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}

	// Send GRPC requests
	for _, syncReq := range syncReqs {
		if _, err := c.client.Sync(ctx, syncReq); err != nil {
			resp.Diagnostics.AddError(
				"create "+c.description.ItemsDescription,
				err.Error())
			return
		}
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
	var diags diag.Diagnostics
	if state, diags = c.read(ctx, state, c.client); diags.HasError() {
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
	var plan, state CollectionResourceModel[T, S]

	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	delReqs, diags := c.DeleteRequests(ctx, state.Items, plan.Items)
	if diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}
	for _, delReq := range delReqs {
		if _, err := c.client.Sync(ctx, delReq); err != nil {
			resp.Diagnostics.AddError(
				"delete "+c.description.ItemsDescription,
				err.Error())
			return
		}
	}

	itemsToUpdate := map[string]T{}
	for name, itemFeatures := range plan.Items {
		// in plan state can have unchanged items which should be ignored
		// missing items before and changed items should be updated
		if oldItemFeatures, ok := state.Items[name]; !ok || itemFeatures.IsDiffer(ctx, oldItemFeatures) {
			itemsToUpdate[name] = itemFeatures
		}
	}

	if len(itemsToUpdate) > 0 {
		tempModel := CollectionResourceModel[T, S]{
			Items: itemsToUpdate,
		}
		updateReqs, diags := tempModel.toSyncReq(ctx, protos.SyncReq_Upsert, c.toSubjOfSync)
		if diags.HasError() {
			resp.Diagnostics.Append(diags...)
			return
		}
		for _, updateReq := range updateReqs {
			if _, err := c.client.Sync(ctx, updateReq); err != nil {
				resp.Diagnostics.AddError(
					"update "+c.description.ItemsDescription,
					err.Error())
				return
			}
		}
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (c *CollectionResource[T, S]) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state CollectionResourceModel[T, S]

	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	delReqs, diags := state.toSyncReq(ctx, protos.SyncReq_Delete, c.toSubjOfSync)
	if diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}

	for _, delReq := range delReqs {
		if _, err := c.client.Sync(ctx, delReq); err != nil {
			resp.Diagnostics.AddError(
				"delete "+c.description.ItemsDescription,
				err.Error())
			return
		}
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

func (c *CollectionResource[T, S]) DeleteRequests(ctx context.Context, stateItems map[string]T, planItems map[string]T) ([]*protos.SyncReq, diag.Diagnostics) { //nolint:lll
	if c.deleteReqs != nil {
		return c.deleteReqs(ctx, stateItems, planItems)
	}

	var (
		res   []*protos.SyncReq
		diags diag.Diagnostics
	)

	itemsToDelete := map[string]T{}
	for name, itemFeatures := range stateItems {
		if _, ok := planItems[name]; !ok {
			// if item is missing in plan state - delete it
			itemsToDelete[name] = itemFeatures
		}
	}

	if len(itemsToDelete) > 0 {
		tempModel := CollectionResourceModel[T, S]{
			Items: itemsToDelete,
		}
		res, diags = tempModel.toSyncReq(ctx, protos.SyncReq_Delete, c.toSubjOfSync)
		if diags.HasError() {
			return nil, diags
		}
	}
	return res, nil
}

var (
	_ resource.Resource              = &CollectionResource[networkItem, protos.SyncNetworks]{}
	_ resource.ResourceWithConfigure = &CollectionResource[networkItem, protos.SyncNetworks]{}
)
