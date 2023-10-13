package provider

import (
	"context"

	protos "github.com/H-BF/protos/pkg/api/sgroups"
	sgAPI "github.com/H-BF/sgroups/internal/api/sgroups"
	model "github.com/H-BF/sgroups/internal/models/sgroups"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func NewFqdnRulesResource() resource.Resource {
	d := Description{
		ResourceDescription: "mapped '`proto:sg(SG_FROM)fqdn(FQDN_RECORD_TO)` keys' -> 'FQDN rule' resource",
		ItemsDescription:    "SG to FQDN rules",
	}
	return &fqdnRulesResource{
		suffix:       "_fqdn_rules",
		description:  d,
		toSubjOfSync: fqdnRulesToProto,
		read:         listFqdnRules,
	}
}

type (
	fqdnRulesResource = CollectionResource[fqdnRuleItem, protos.SyncFqdnRules]

	fqdnRulesResourceModel = CollectionResourceModel[fqdnRuleItem, protos.SyncFqdnRules]

	fqdnRuleItem struct {
		Logs  types.Bool   `tfsdk:"logs"`
		Ports []AccessPort `tfsdk:"ports"`
	}
)

func (item fqdnRuleItem) ResourceAttributes() map[string]schema.Attribute {
	ap := AccessPort{}
	return map[string]schema.Attribute{
		"logs": schema.BoolAttribute{
			Description: "toggle logging on every rule in security group",
			Optional:    true,
			Computed:    true,
			Default:     booldefault.StaticBool(false),
		},
		"ports": schema.ListNestedAttribute{
			Description: "access ports",
			Optional:    true,
			NestedObject: schema.NestedAttributeObject{
				Attributes: ap.ResourceAttributes(),
			},
			PlanModifiers: []planmodifier.List{ListAccessPortsModifier()},
		},
	}
}

func (item fqdnRuleItem) IsDiffer(oldFqdnRule fqdnRuleItem) bool {
	var itemModelPorts, oldModelPorts []model.SGRulePorts

	// `toModelPorts` can not be failed because its validate then created in `fqdnRulesToProto`
	itemModelPorts, _ = toModelPorts(item.Ports)
	oldModelPorts, _ = toModelPorts(oldFqdnRule.Ports)

	return !(item.Logs.Equal(oldFqdnRule.Logs) && model.AreRulePortsEq(itemModelPorts, oldModelPorts))
}

func (item fqdnRuleItem) portsToProto() []*protos.AccPorts {
	var ret []*protos.AccPorts
	for _, port := range item.Ports {
		ret = append(ret, port.toProto())
	}
	return ret
}

func fqdnRulesToProto(ctx context.Context, items map[string]fqdnRuleItem) (*protos.SyncFqdnRules, diag.Diagnostics) {
	syncFqdnRules := &protos.SyncFqdnRules{}
	var diags diag.Diagnostics
	for key, features := range items {
		keyData, err := restoreSgToFqdnKey(key)
		if err != nil {
			diags.AddError(
				"Error conversion to proto",
				"Could not parse key: "+err.Error())
			return nil, diags
		}

		// this conversion necessary to validate string with ports
		if _, err := toModelPorts(features.Ports); err != nil {
			diags.AddError(
				"Error conversion to proto",
				"Could not validate ports: "+err.Error())
			return nil, diags
		}

		syncFqdnRules.Rules = append(syncFqdnRules.Rules, &protos.FqdnRule{
			SgFrom:    keyData.from,
			FQDN:      keyData.to,
			Transport: keyData.proto,
			Logs:      features.Logs.ValueBool(),
			Ports:     features.portsToProto(),
		})

	}
	return syncFqdnRules, diags
}

func listFqdnRules(ctx context.Context, state fqdnRulesResourceModel, client *sgAPI.Client) (fqdnRulesResourceModel, diag.Diagnostics) {
	var diags diag.Diagnostics

	sgNames, err := getSgNames(state.Items)
	if err != nil {
		diags.AddError("Error reading resource state",
			"Cannot parse rule keys: "+err.Error())
	}
	req := &protos.FindFqdnRulesReq{
		SgFrom: sgNames,
	}

	resp, err := client.FindFqdnRules(ctx, req)
	if err != nil {
		diags.AddError("Error reading resource state",
			"Could not perform FindFqdnRules GRPC call: "+err.Error())
		return fqdnRulesResourceModel{}, diags
	}

	newItems := make(map[string]fqdnRuleItem, len(state.Items))
	for _, fqdnRule := range resp.GetRules() {
		if fqdnRule != nil {
			var ports []AccessPort
			for _, accPorts := range fqdnRule.GetPorts() {
				if accPorts != nil {
					ports = append(ports, AccessPort{
						Source:      types.StringValue(accPorts.S),
						Destination: types.StringValue(accPorts.D),
					})
				}
			}
			keyData := fromFqdnRule(fqdnRule)
			newItems[keyData.sgToFqdnKey()] = fqdnRuleItem{
				Logs:  types.BoolValue(fqdnRule.GetLogs()),
				Ports: ports,
			}
		}
	}

	state.Items = newItems
	return state, diags
}

func getSgNames(items map[string]fqdnRuleItem) ([]string, error) {
	var sgNames []string

	for key := range items {
		keyData, err := restoreSgToFqdnKey(key)
		if err != nil {
			return nil, err
		}
		sgNames = append(sgNames, keyData.from)
	}

	return sgNames, nil
}
