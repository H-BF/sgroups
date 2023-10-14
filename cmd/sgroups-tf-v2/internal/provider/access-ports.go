package provider

import (
	protos "github.com/H-BF/protos/pkg/api/sgroups"

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

func (p AccessPorts) ResourceAttributes() map[string]schema.Attribute {
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

func (p AccessPorts) toProto() *protos.AccPorts {
	return &protos.AccPorts{
		S: p.Source.ValueString(),
		D: p.Destination.ValueString(),
	}
}
