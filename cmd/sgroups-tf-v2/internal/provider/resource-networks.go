package provider

import (
	"context"

	"github.com/H-BF/protos/pkg/api/common"
	protos "github.com/H-BF/protos/pkg/api/sgroups"
	"github.com/H-BF/sgroups/cmd/sgroups-tf-v2/internal/validators"
	sgAPI "github.com/H-BF/sgroups/internal/api/sgroups"

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
		toProto:     networksToProto,
		read:        listNetworks,
		sr:          networkItem{},
	}
}

type (
	networksResource      = CollectionResource[networkItem, protos.SyncNetworks]
	networksResourceModel = CollectionResourceModel[networkItem, protos.SyncNetworks]

	networkItem struct {
		Cidr types.String `tfsdk:"cidr"`
	}
)

func (item networkItem) ResourceAttributes() map[string]schema.Attribute {
	return map[string]schema.Attribute{
		"cidr": schema.StringAttribute{
			Required: true,
			Validators: []validator.String{
				validators.IsCIDR(),
			},
		},
	}
}

func (item networkItem) Changed(oldState SingleResource) bool {
	oldNetwork, ok := oldState.(networkItem)
	if !ok {
		panic("networkItem type expected")
	}
	return !item.Cidr.Equal(oldNetwork.Cidr)
}

func networksToProto(_ context.Context, items map[string]networkItem) (*protos.SyncNetworks, diag.Diagnostics) {
	sn := &protos.SyncNetworks{}
	var diags diag.Diagnostics
	for name, netFeatures := range items {
		sn.Networks = append(sn.Networks, &protos.Network{
			Name:    name,
			Network: &common.Networks_NetIP{CIDR: netFeatures.Cidr.ValueString()},
		})
	}
	return sn, diags
}

func listNetworks(ctx context.Context, state networksResourceModel, client *sgAPI.Client) (networksResourceModel, diag.Diagnostics) {
	var diags diag.Diagnostics
	listReq := protos.ListNetworksReq{
		NeteworkNames: state.getNames(),
	}

	listResp, err := client.ListNetworks(ctx, &listReq)
	if err != nil {
		diags.AddError("Error reading resource state",
			"Could not perform ListNetworks GRPC call: "+err.Error())
		return networksResourceModel{}, diags
	}

	newItems := make(map[string]networkItem, len(state.Items))
	for _, nw := range listResp.GetNetworks() {
		if nw != nil {
			newItems[nw.GetName()] = networkItem{Cidr: types.StringValue(nw.GetNetwork().GetCIDR())}
		}
	}

	return state, nil
}
