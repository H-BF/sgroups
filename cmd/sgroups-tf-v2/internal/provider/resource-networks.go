package provider

import (
	"context"

	protos "github.com/H-BF/protos/pkg/api/sgroups"
	"github.com/H-BF/sgroups/cmd/sgroups-tf-v2/internal/validators"
	sgAPI "github.com/H-BF/sgroups/internal/api/sgroups"

	"github.com/ahmetb/go-linq/v3"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func NewNetworksResource() resource.Resource {
	d := Description{
		ResourceDescription: "mapped 'Name' -> 'Network' resources",
		ItemsDescription:    "Networks",
	}
	return &networksResource{
		suffix:      "_networks",
		description: d,
		readState:   readNetworks,
	}
}

type (
	networksResource = CollectionResource[networkItem, tfNetworks2Backend]
	networkItem      struct {
		Name types.String `tfsdk:"name"`
		Cidr types.String `tfsdk:"cidr"`
	}
)

func (item networkItem) Attributes() map[string]schema.Attribute {
	return map[string]schema.Attribute{
		"name": schema.StringAttribute{
			Description: "security group name",
			Required:    true,
		},
		"cidr": schema.StringAttribute{
			Required: true,
			Validators: []validator.String{
				validators.IsCIDR(),
			},
		},
	}
}

func (item networkItem) IsDiffer(ctx context.Context, other networkItem) bool {
	return !(item.Name.Equal(other.Name) &&
		item.Cidr.Equal(other.Cidr))
}

func readNetworks(ctx context.Context, state NamedResources[networkItem], client *sgAPI.Client) (NamedResources[networkItem], diag.Diagnostics) {
	var (
		diags    diag.Diagnostics
		err      error
		listResp *protos.ListNetworksResp
	)
	newState := NewNamedResources[networkItem]()
	if len(state.Items) > 0 {
		var listReq protos.ListNetworksReq

		linq.From(state.Items).Select(func(i interface{}) interface{} {
			return i.(linq.KeyValue).Value.(networkItem).Name.ValueString()
		}).Distinct().ToSlice(&listReq.NetworkNames)

		listResp, err = client.ListNetworks(ctx, &listReq)
		if err != nil {
			diags.AddError("read networks", err.Error())
			return NamedResources[networkItem]{}, diags
		}
	}

	for _, nw := range listResp.GetNetworks() {
		if _, ok := state.Items[nw.GetName()]; ok {
			newState.Items[nw.GetName()] = networkItem{
				Name: types.StringValue(nw.GetName()),
				Cidr: types.StringValue(nw.GetNetwork().GetCIDR())}
		}
	}

	return newState, nil
}
