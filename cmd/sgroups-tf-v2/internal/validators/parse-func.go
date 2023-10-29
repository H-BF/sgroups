package validators

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
)

type parseFuncValidator struct {
	description string
	parseFunc   func(s string) error
}

func (d parseFuncValidator) Description(ctx context.Context) string {
	return d.description
}

func (d parseFuncValidator) MarkdownDescription(ctx context.Context) string {
	return d.Description(ctx)
}

func (d parseFuncValidator) ValidateString(ctx context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.ValueString() == "" {
		return
	}

	err := d.parseFunc(req.ConfigValue.ValueString())
	if err != nil {
		resp.Diagnostics.Append(
			invalidAttributeValueDiagnostic(req.Path, d.Description(ctx), req.ConfigValue.ValueString()),
		)
	}
}

var _ validator.String = &parseFuncValidator{}
