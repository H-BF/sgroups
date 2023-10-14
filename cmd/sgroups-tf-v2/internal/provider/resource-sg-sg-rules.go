package provider

import (
	"context"
	"fmt"
	"strings"

	"github.com/H-BF/protos/pkg/api/common"
	protos "github.com/H-BF/protos/pkg/api/sgroups"
	sgAPI "github.com/H-BF/sgroups/internal/api/sgroups"
	model "github.com/H-BF/sgroups/internal/models/sgroups"
	"github.com/ahmetb/go-linq/v3"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func NewSgToSgRulesResource() resource.Resource {
	d := Description{
		ResourceDescription: "mapped 'proto:sg(sg-from)sg(sg-to)' -> 'SG-SG' rule resource",
		ItemsDescription:    "SG -> SG rules",
	}
	return &sgToSgRulesResource{
		suffix:       "_rules",
		description:  d,
		toSubjOfSync: sgSgRules2SyncSubj,
		read:         readSgSgRules,
	}
}

type (
	sgToSgRulesResource = CollectionResource[sgSgRule, protos.SyncSGRules]

	sgToSgRulesResourceModel = CollectionResourceModel[sgSgRule, protos.SyncSGRules]

	sgSgRule struct {
		Proto  types.String  `tfsdk:"proto"`
		SgFrom types.String  `tfsdk:"sg_from"`
		SgTo   types.String  `tfsdk:"sg_to"`
		Ports  []AccessPorts `tfsdk:"ports"`
		Logs   types.Bool    `tfsdk:"logs"`
	}

	sgSgRuleKey struct {
		proto  string
		sgFrom string
		sgTo   string
	}
)

// String -
func (k sgSgRuleKey) String() string {
	return fmt.Sprintf("%s:sg(%s)sg(%s)",
		strings.ToLower(k.proto), k.sgFrom, k.sgTo)
}

// Key -
func (item sgSgRule) Key() *sgSgRuleKey {
	return &sgSgRuleKey{
		proto:  item.Proto.String(),
		sgFrom: item.SgFrom.String(),
		sgTo:   item.SgTo.String(),
	}
}

func (item sgSgRule) IsDiffer(other sgSgRule) bool {
	var itemModelPorts, otherModelPorts []model.SGRulePorts

	// `toModelPorts` can not be failed because its validate then created in `fqdnRulesToProto`
	itemModelPorts, _ = toModelPorts(item.Ports)
	otherModelPorts, _ = toModelPorts(other.Ports)
	return !(strings.EqualFold(item.Proto.String(), other.Proto.String()) &&
		item.SgFrom.Equal(other.SgFrom) &&
		item.SgTo.Equal(other.SgTo) &&
		item.Logs.Equal(other.Logs) &&
		model.AreRulePortsEq(itemModelPorts, otherModelPorts))
}

func (item sgSgRule) ResourceAttributes() map[string]schema.Attribute {
	return map[string]schema.Attribute{
		"proto": schema.StringAttribute{
			Description: "IP-L4 proto <tcp|udp>",
			Required:    true,
			Validators: []validator.String{
				stringvalidator.OneOf(
					"tcp",
					"udp",
				),
			},
		},
		"sg_from": schema.StringAttribute{
			Description: "Security Group to",
			Required:    true,
		},
		"sg_to": schema.StringAttribute{
			Description: "Security Group to",
			Required:    true,
		},
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
				Attributes: AccessPorts{}.ResourceAttributes(),
			},
			PlanModifiers: []planmodifier.List{ListAccessPortsModifier()},
		},
	}
}

func sgSgRules2SyncSubj(ctx context.Context, items map[string]sgSgRule) (*protos.SyncSGRules, diag.Diagnostics) {
	syncObj := new(protos.SyncSGRules)
	var diags diag.Diagnostics
	for _, features := range items {
		// this conversion necessary to validate string with ports
		if _, err := toModelPorts(features.Ports); err != nil {
			diags.AddError("ports conv", err.Error())
			return nil, diags
		}
		protoValue, ok := common.Networks_NetIP_Transport_value[strings.ToUpper(
			features.Proto.String(),
		)]
		if !ok {
			diags.AddError(
				"proto conv",
				fmt.Sprintf("no proto conv tor value(%s)", features.Proto.String()))
			return nil, diags
		}
		syncObj.Rules = append(syncObj.Rules, &protos.Rule{
			SgFrom:    features.SgFrom.String(),
			SgTo:      features.SgTo.String(),
			Transport: common.Networks_NetIP_Transport(protoValue),
			Logs:      features.Logs.ValueBool(),
			Ports:     portsToProto(features.Ports),
		})
	}
	return syncObj, diags
}

func readSgSgRules(ctx context.Context, state sgToSgRulesResourceModel, client *sgAPI.Client) (sgToSgRulesResourceModel, diag.Diagnostics) {
	var diags diag.Diagnostics
	newState := sgToSgRulesResourceModel{Items: make(map[string]sgSgRule)}
	var resp *protos.RulesResp
	if len(state.Items) > 0 {
		var req protos.FindRulesReq
		linq.From(state.Items).
			Select(func(i interface{}) interface{} {
				return i.(linq.KeyValue).Value.(sgSgRule).SgFrom
			}).Distinct().ToSlice(&req.SgFrom)
		linq.From(state.Items).
			Select(func(i interface{}) interface{} {
				return i.(linq.KeyValue).Value.(sgSgRule).SgTo
			}).Distinct().ToSlice(&req.SgTo)
		var err error
		if resp, err = client.FindRules(ctx, &req); err != nil {
			diags.AddError("read sg-sg-rules", err.Error())
			return newState, diags
		}
	}
	for _, sgRule := range resp.GetRules() {
		var ports []AccessPorts
		for _, accPorts := range sgRule.GetPorts() {
			ports = append(ports, AccessPorts{
				Source:      types.StringValue(accPorts.S),
				Destination: types.StringValue(accPorts.D),
			})
		}
		it := sgSgRule{
			Proto:  types.StringValue(strings.ToLower(sgRule.GetTransport().String())),
			SgFrom: types.StringValue(sgRule.GetSgFrom()),
			SgTo:   types.StringValue(sgRule.GetSgTo()),
			Logs:   types.BoolValue(sgRule.GetLogs()),
			Ports:  ports,
		}
		k := it.Key().String()
		if _, ok := state.Items[k]; ok {
			newState.Items[k] = it
		}
	}
	return newState, diags
}
