package provider

import (
	"context"

	protos "github.com/H-BF/protos/pkg/api/sgroups"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type (
	AccessPorts struct {
		Source      types.String `tfsdk:"s"`
		Destination types.String `tfsdk:"d"`
	}
)

func (p AccessPorts) Attributes() map[string]schema.Attribute {
	return map[string]schema.Attribute{
		"s": schema.StringAttribute{
			Description: "source port/ports range",
			Optional:    true,
			Computed:    true,
			Default:     stringdefault.StaticString(""),
		},
		"d": schema.StringAttribute{
			Description: "destination port/ports range",
			Optional:    true,
			Computed:    true,
			Default:     stringdefault.StaticString(""),
		},
	}
}

func (p AccessPorts) AttrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"s": types.StringType,
		"d": types.StringType,
	}
}

func (p AccessPorts) toProto() *protos.AccPorts {
	return &protos.AccPorts{
		S: p.Source.ValueString(),
		D: p.Destination.ValueString(),
	}
}

func accPortsRangeToProto(data []AccessPorts) []*protos.AccPorts {
	var ret []*protos.AccPorts
	for _, port := range data {
		ret = append(ret, port.toProto())
	}
	return ret
}

func accPortsRangeFromTF(ctx context.Context, tfValue types.List) (ret []AccessPorts, diags diag.Diagnostics) {
	diags.Append(tfValue.ElementsAs(ctx, &ret, false)...)
	if diags.HasError() {
		return ret, diags
	}
	// this conversion necessary to validate string with ports
	if _, err := toModelPorts(ret); err != nil {
		diags.AddError("ports conv", err.Error())
		return ret, diags
	}
	return ret, diags
}
