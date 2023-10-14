package provider

import (
	"context"
	"errors"

	model "github.com/H-BF/sgroups/internal/models/sgroups"

	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
)

func ListAccessPortsModifier() planmodifier.List {
	return &listAccessPortsModifier{
		description: "plan to modify access ports list",
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
			"State value conversion failed: "+err.Error())
		return
	}
	planModelPorts, err := toModelPorts(planPorts)
	if err != nil {
		resp.Diagnostics.AddError("Plan modifier error",
			"Plan value conversion failed: "+err.Error())
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
		sourceRanges, err := model.PortSource(port.Source.ValueString()).ToPortRanges()
		if err != nil {
			return ret, errors.New("source ports conversion error: " + err.Error())
		}
		destRanges, err := model.PortSource(port.Destination.ValueString()).ToPortRanges()
		if err != nil {
			return ret, errors.New("destination ports conversion error: " + err.Error())
		}
		modelPorts := model.SGRulePorts{
			S: sourceRanges,
			D: destRanges,
		}
		if modelPorts.Validate() != nil {
			return nil, errors.New("Validation failed: " + err.Error())
		}
		ret = append(ret, modelPorts)
	}
	return ret, nil
}
