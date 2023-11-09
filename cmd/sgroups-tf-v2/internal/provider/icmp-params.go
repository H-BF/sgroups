package provider

import (
	"math"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type IcmpParameters struct {
	Logs  types.Bool `tfsdk:"logs"`
	Trace types.Bool `tfsdk:"trace"`
	Type  types.Set  `tfsdk:"type"`
}

func (params IcmpParameters) ResourceAttributes() map[string]schema.Attribute {
	return map[string]schema.Attribute{
		"logs": schema.BoolAttribute{
			Description: "toggle logging on every rule in security group",
			Optional:    true,
			Computed:    true,
			Default:     booldefault.StaticBool(false),
		},
		"trace": schema.BoolAttribute{
			Description: "toggle logging on every rule in security group",
			Optional:    true,
			Computed:    true,
			Default:     booldefault.StaticBool(false),
		},
		"type": schema.SetAttribute{
			Description: "Set of ICMP types",
			Required:    true,
			ElementType: types.Int64Type,
			Validators: []validator.Set{
				setvalidator.ValueInt64sAre(int64validator.Between(0, math.MaxUint8)),
			},
		},
	}
}

func (params IcmpParameters) AttrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"logs":  types.BoolType,
		"trace": types.BoolType,
		"type": types.SetType{
			ElemType: types.Int64Type,
		},
	}
}
