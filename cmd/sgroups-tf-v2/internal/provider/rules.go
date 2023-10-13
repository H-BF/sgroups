package provider

import (
	"context"

	protos "github.com/H-BF/protos/pkg/api/sgroups"
	sgAPI "github.com/H-BF/sgroups/internal/api/sgroups"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func NewSgToSgRulesResource() resource.Resource {
	d := Description{
		ResourceDescription: "mapped '`proto:sg(SG_FROM)sg(SG_TO)` keys' -> 'SG rule' resource",
		ItemsDescription:    "SG to SG rules",
	}
	return &sgToSgRulesResource{
		suffix:       "_rules",
		description:  d,
		toSubjOfSync: rulesToProto,
		read:         listRules,
	}
}

type (
	sgToSgRulesResource = CollectionResource[ruleItem, protos.SyncSGRules]

	sgToSgRulesResourceModel = CollectionResourceModel[ruleItem, protos.SyncSGRules]

	ruleItem = fqdnRuleItem
)

func rulesToProto(ctx context.Context, items map[string]ruleItem) (*protos.SyncSGRules, diag.Diagnostics) {
	syncObj := &protos.SyncSGRules{}
	var diags diag.Diagnostics
	for key, features := range items {
		keyData, err := restoreSgToSgKey(key)
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

		syncObj.Rules = append(syncObj.Rules, &protos.Rule{
			SgFrom:    keyData.from,
			SgTo:      keyData.to,
			Transport: keyData.proto,
			Logs:      features.Logs.ValueBool(),
			Ports:     features.portsToProto(),
		})
	}
	return syncObj, diags
}

func listRules(ctx context.Context, state sgToSgRulesResourceModel, client *sgAPI.Client) (sgToSgRulesResourceModel, diag.Diagnostics) {
	var diags diag.Diagnostics

	sgFromNames, sgToNames, err := getSgNames(state.Items, restoreSgToSgKey)
	if err != nil {
		diags.AddError("Error reading resource state",
			"Cannot parse rule keys: "+err.Error())
	}
	req := &protos.FindRulesReq{
		SgFrom: sgFromNames,
		SgTo:   sgToNames,
	}

	resp, err := client.FindRules(ctx, req)
	if err != nil {
		diags.AddError("Error reading resource state",
			"Could not perform FindRules GRPC call: "+err.Error())
		return sgToSgRulesResourceModel{}, diags
	}

	newItems := make(map[string]ruleItem, len(state.Items))
	for _, sgRule := range resp.GetRules() {
		if sgRule != nil {
			var ports []AccessPort
			for _, accPorts := range sgRule.GetPorts() {
				if accPorts != nil {
					ports = append(ports, AccessPort{
						Source:      types.StringValue(accPorts.S),
						Destination: types.StringValue(accPorts.D),
					})
				}
			}
			keyData := fromSgRule(sgRule)
			newItems[keyData.sgToSgKey()] = ruleItem{
				Logs:  types.BoolValue(sgRule.GetLogs()),
				Ports: ports,
			}
		}
	}

	state.Items = newItems
	return state, diags
}
