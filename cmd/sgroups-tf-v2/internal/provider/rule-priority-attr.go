package provider

import (
	"fmt"

	protos "github.com/H-BF/protos/pkg/api/sgroups"
	"github.com/H-BF/sgroups/cmd/sgroups-tf-v2/internal/validators"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

const rulePriorityAttrLabel = "priority"

// RulePriority -
type RulePriority = types.Int64

func rulePriorityAttr() schema.Int64Attribute {
	return schema.Int64Attribute{
		Description: "Rule priority in chain",
		Optional:    true,
		Computed:    true,
		Default:     int64NullDefaulter{},
		Validators:  []validator.Int64{validators.CheckRulePriority()},
	}
}

func rulePriority2proto(src RulePriority) (ret *protos.RulePriority, di diag.Diagnostic) {
	if src.IsUnknown() {
		di = diag.NewErrorDiagnostic("RulePriority", "state is unknown")
	} else {
		ret = new(protos.RulePriority)
		if !src.IsNull() {
			v := src.ValueInt64()
			ret.Value = &protos.RulePriority_Some{
				Some: int32(v),
			}
		}
	}
	return ret, di
}

func rulePriorityFromProto(src *protos.RulePriority) (ret RulePriority, di diag.Diagnostic) {
	switch t := src.GetValue().(type) {
	case *protos.RulePriority_Some:
		ret = types.Int64Value(int64(t.Some))
	case nil:
		ret = types.Int64Null()
	default:
		di = diag.NewErrorDiagnostic(
			"got unexpected value type for protos.RulePriority",
			fmt.Sprintf("type '%T'", t),
		)
	}
	return ret, di
}
