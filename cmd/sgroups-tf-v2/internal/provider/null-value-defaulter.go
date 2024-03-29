package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/resource/schema/defaults"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type nullDefaulterBase struct{}

type int64NullDefaulter struct {
	nullDefaulterBase
}

// DefaultInt64 -
func (int64NullDefaulter) DefaultInt64(ctx context.Context, req defaults.Int64Request, resp *defaults.Int64Response) {
	resp.PlanValue = types.Int64Null()
}

// Description returns a human-readable description of the default value handler.
func (nullDefaulterBase) Description(_ context.Context) string {
	return "null value as default"
}

// MarkdownDescription returns a markdown description of the default value handler.
func (d nullDefaulterBase) MarkdownDescription(ctx context.Context) string {
	return d.Description(ctx)
}
