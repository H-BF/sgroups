package provider

import (
	"context"

	"github.com/H-BF/protos/pkg/api/common"
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
		suffix:       "_networks",
		description:  d,
		toSubjOfSync: networks2SyncSubj,
		read:         readNetworks,
	}
}

type (
	networksResource      = CollectionResource[networkItem, protos.SyncNetworks]
	networksResourceModel = CollectionResourceModel[networkItem, protos.SyncNetworks]

	networkItem struct {
		Name types.String `tfsdk:"name"`
		Cidr types.String `tfsdk:"cidr"`
	}
)

func (item networkItem) ResourceAttributes() map[string]schema.Attribute {
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

func (item networkItem) IsDiffer(oldState networkItem) bool {
	return !(item.Name.Equal(oldState.Name) &&
		item.Cidr.Equal(oldState.Cidr))
}

func networks2SyncSubj(_ context.Context, items map[string]networkItem) (*protos.SyncNetworks, diag.Diagnostics) {
	sn := &protos.SyncNetworks{}
	var diags diag.Diagnostics
	for _, netFeatures := range items {
		sn.Networks = append(sn.Networks, &protos.Network{
			Name:    netFeatures.Name.ValueString(),
			Network: &common.Networks_NetIP{CIDR: netFeatures.Cidr.ValueString()},
		})
	}
	return sn, diags
}

func readNetworks(ctx context.Context, state networksResourceModel, client *sgAPI.Client) (networksResourceModel, diag.Diagnostics) {
	var (
		diags    diag.Diagnostics
		err      error
		listResp *protos.ListNetworksResp
	)
	newState := networksResourceModel{Items: make(map[string]networkItem)}
	if len(state.Items) > 0 {
		var listReq protos.ListNetworksReq

		linq.From(state.Items).Select(func(i interface{}) interface{} {
			return i.(linq.KeyValue).Value.(networkItem).Name.ValueString()
		}).Distinct().ToSlice(&listReq.NeteworkNames)

		listResp, err = client.ListNetworks(ctx, &listReq)
		if err != nil {
			diags.AddError("Error reading resource state",
				"Could not perform ListNetworks GRPC call: "+err.Error())
			return networksResourceModel{}, diags
		}
	}

	for _, nw := range listResp.GetNetworks() {
		if nw != nil {
			if _, ok := state.Items[nw.GetName()]; ok {
				newState.Items[nw.GetName()] = networkItem{
					Name: types.StringValue(nw.GetName()),
					Cidr: types.StringValue(nw.GetNetwork().GetCIDR())}
			}
		}
	}

	return newState, nil
}
