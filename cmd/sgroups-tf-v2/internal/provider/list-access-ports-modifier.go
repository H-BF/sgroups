package provider

import (
	"context"

	model "github.com/H-BF/sgroups/internal/models/sgroups"

	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
)

func ListAccessPortsModifier() planmodifier.List {
	return &listAccessPortsModifier{
		description: "plan to modify access ports",
	}
}

type listAccessPortsModifier struct {
	description string
}

var _ planmodifier.List = &listAccessPortsModifier{}

func (m listAccessPortsModifier) Description(_ context.Context) string {
	return m.description
}

func (m listAccessPortsModifier) MarkdownDescription(_ context.Context) string {
	return m.description
}

func (*listAccessPortsModifier) PlanModifyList(ctx context.Context, req planmodifier.ListRequest, resp *planmodifier.ListResponse) {
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

	var statePorts, planPorts []AccessPorts
	resp.Diagnostics.Append(req.StateValue.ElementsAs(ctx, &statePorts, false)...)
	resp.Diagnostics.Append(req.PlanValue.ElementsAs(ctx, &planPorts, false)...)
	if resp.Diagnostics.HasError() {
		return
	}

	stateModelPorts, err := toModelPorts(statePorts)
	if err != nil {
		resp.Diagnostics.AddError("Plan modifier error",
			err.Error())
		return
	}
	planModelPorts, err := toModelPorts(planPorts)
	if err != nil {
		resp.Diagnostics.AddError("Plan modifier error",
			err.Error())
		return
	}

	if model.AreRulePortsEq(stateModelPorts, planModelPorts) {
		resp.PlanValue = req.StateValue
	}
}

func toModelPorts(ports []AccessPorts) ([]model.SGRulePorts, error) {
	var ret []model.SGRulePorts

	for _, port := range ports {
		var err error
		var sourceRanges model.PortRanges
		var destRanges model.PortRanges
		sourceRanges, err = model.PortSource(port.Source.ValueString()).ToPortRanges()
		if err != nil {
			return ret, err
		}
		destRanges, err = model.PortSource(port.Destination.ValueString()).ToPortRanges()
		if err != nil {
			return ret, err
		}
		modelPorts := model.SGRulePorts{
			S: sourceRanges,
			D: destRanges,
		}
		ret = append(ret, modelPorts)
	}
	return ret, nil
}
