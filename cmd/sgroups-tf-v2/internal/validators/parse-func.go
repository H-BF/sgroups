package validators

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
)

type validatorBase struct {
	description string
}

type stringValidator struct {
	validatorBase
	validateFn func(s string) error
}

type intValidator struct {
	validatorBase
	validateFn func(context.Context, validator.Int64Request, *validator.Int64Response)
}

// Description -
func (d validatorBase) Description(_ context.Context) string {
	return d.description
}

// MarkdownDescription -
func (d validatorBase) MarkdownDescription(ctx context.Context) string {
	return d.Description(ctx)
}

// ValidateString -
func (d stringValidator) ValidateString(ctx context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	val := req.ConfigValue.ValueString()
	if val == "" {
		return
	}
	if err := d.validateFn(val); err != nil {
		resp.Diagnostics.Append(
			invalidAttributeValueDiagnostic(req.Path, d.Description(ctx), req.ConfigValue.ValueString()),
		)
	}
}

// ValidateInt64 -
func (d intValidator) ValidateInt64(ctx context.Context, req validator.Int64Request, resp *validator.Int64Response) {
	d.validateFn(ctx, req, resp)
}

var (
	_ validator.String = (*stringValidator)(nil)
	_ validator.Int64  = (*intValidator)(nil)
)
