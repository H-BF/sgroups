package planmodifiers

import (
	"context"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
)

func CommaSeparatedSet(description string, splitter func(string) []string) planmodifier.String {
	return &commaSeparatedSet{
		description: description,
		splitter:    splitter,
	}
}

type commaSeparatedSet struct {
	description string
	splitter    func(string) []string
}

var _ planmodifier.String = &commaSeparatedSet{}

func (m commaSeparatedSet) Description(_ context.Context) string {
	return m.description
}

func (m commaSeparatedSet) MarkdownDescription(_ context.Context) string {
	return m.description
}

func (m commaSeparatedSet) PlanModifyString(_ context.Context, req planmodifier.StringRequest, resp *planmodifier.StringResponse) {
	// Do not replace on resource creation.
	if req.State.Raw.IsNull() {
		return
	}

	// Do not replace on resource destroy.
	if req.Plan.Raw.IsNull() {
		return
	}

	// Do not replace if the plan and state values are equal.
	if req.PlanValue.Equal(req.StateValue) {
		return
	}

	oldValueSorted := strings.Join(m.splitter(req.StateValue.ValueString()), ",")
	newValueSorted := strings.Join(m.splitter(req.PlanValue.ValueString()), ",")

	if oldValueSorted == newValueSorted {
		// sets are same but values are reordered - use prior state value
		resp.PlanValue = req.StateValue
	}
}
