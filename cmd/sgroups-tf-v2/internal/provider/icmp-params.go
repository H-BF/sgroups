package provider

import (
	"context"
	"math"

	protos "github.com/H-BF/protos/pkg/api/sgroups"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
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

func (params IcmpParameters) nullObj() types.Object {
	return types.ObjectNull(params.AttrTypes())
}

func (params IcmpParameters) fromProto(ctx context.Context, proto *protos.SgIcmpRule) (types.Object, diag.Diagnostics) {
	typeSet, d := types.SetValueFrom(ctx, types.Int64Type, proto.ICMP.GetTypes())
	if d.HasError() {
		return params.nullObj(), d
	}
	value := types.ObjectValueMust(params.AttrTypes(), map[string]attr.Value{
		"logs":  types.BoolValue(proto.GetLogs()),
		"trace": types.BoolValue(proto.GetTrace()),
		"type":  typeSet,
	})
	return value, nil
}
