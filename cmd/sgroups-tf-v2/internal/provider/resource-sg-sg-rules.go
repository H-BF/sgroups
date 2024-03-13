package provider

import (
	"context"
	"fmt"
	"strings"

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
		suffix:      "_rules",
		description: d,
		readState:   readSgSgRules,
	}
}

type (
	sgToSgRulesResource = CollectionResource[sgSgRule, tfSgSgRules2Backend]

	sgSgRule struct {
		Transport types.String `tfsdk:"transport"`
		SgFrom    types.String `tfsdk:"sg_from"`
		SgTo      types.String `tfsdk:"sg_to"`
		Ports     types.List   `tfsdk:"ports"`
		Logs      types.Bool   `tfsdk:"logs"`
		// TODO: add Trace param
		Action types.String `tfsdk:"action"`
	}

	sgSgRuleKey struct {
		transport string
		sgFrom    string
		sgTo      string
	}
)

// String -
func (k sgSgRuleKey) String() string {
	return fmt.Sprintf("%s:sg(%s)sg(%s)",
		strings.ToLower(k.transport), k.sgFrom, k.sgTo)
}

// Key -
func (item sgSgRule) Key() *sgSgRuleKey {
	return &sgSgRuleKey{
		transport: item.Transport.ValueString(),
		sgFrom:    item.SgFrom.ValueString(),
		sgTo:      item.SgTo.ValueString(),
	}
}

func (item sgSgRule) IsDiffer(ctx context.Context, other sgSgRule) bool { //nolint:dupl
	var (
		itemModelPorts, otherModelPorts []model.SGRulePorts
		itemAccPorts, otherAccPorts     []AccessPorts
	)

	_ = item.Ports.ElementsAs(ctx, &itemAccPorts, false)
	_ = other.Ports.ElementsAs(ctx, &otherAccPorts, false)

	// `toModelPorts` can not be failed because its validate then created
	itemModelPorts, _ = toModelPorts(itemAccPorts)
	otherModelPorts, _ = toModelPorts(otherAccPorts)
	return !(strings.EqualFold(item.Transport.ValueString(), other.Transport.ValueString()) &&
		item.SgFrom.Equal(other.SgFrom) &&
		item.SgTo.Equal(other.SgTo) &&
		item.Logs.Equal(other.Logs) &&
		item.Action.Equal(other.Action) &&
		model.AreRulePortsEq(itemModelPorts, otherModelPorts))
}

func (item sgSgRule) Attributes() map[string]schema.Attribute { //nolint:dupl
	return map[string]schema.Attribute{
		"transport": schema.StringAttribute{
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
			Description: "Security Group from",
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
				Attributes: AccessPorts{}.Attributes(),
			},
			PlanModifiers: []planmodifier.List{ListAccessPortsModifier()},
		},
		"action": schema.StringAttribute{
			Description: "Rule action on packets in chain",
			Required:    true,
			Validators:  []validator.String{actionValidator},
		},
	}
}

func readSgSgRules(ctx context.Context, state NamedResources[sgSgRule], client *sgAPI.Client) (NamedResources[sgSgRule], diag.Diagnostics) {
	var diags diag.Diagnostics
	newState := NewNamedResources[sgSgRule]()
	var resp *protos.RulesResp
	if len(state.Items) > 0 {
		var req protos.FindRulesReq
		linq.From(state.Items).
			Select(func(i interface{}) interface{} {
				return i.(linq.KeyValue).Value.(sgSgRule).SgFrom.ValueString()
			}).Distinct().ToSlice(&req.SgFrom)
		linq.From(state.Items).
			Select(func(i interface{}) interface{} {
				return i.(linq.KeyValue).Value.(sgSgRule).SgTo.ValueString()
			}).Distinct().ToSlice(&req.SgTo)
		var err error
		if resp, err = client.FindRules(ctx, &req); err != nil {
			diags.AddError("read sg-sg-rules", err.Error())
			return newState, diags
		}
	}
	for _, sgRule := range resp.GetRules() {
		accPorts := []AccessPorts{}
		for _, p := range sgRule.GetPorts() {
			accPorts = append(accPorts, AccessPorts{
				Source:      types.StringValue(p.S),
				Destination: types.StringValue(p.D),
			})
		}
		portsList, d := types.ListValueFrom(ctx, types.ObjectType{AttrTypes: AccessPorts{}.AttrTypes()}, accPorts)
		diags.Append(d...)
		it := sgSgRule{
			Transport: types.StringValue(strings.ToLower(sgRule.GetTransport().String())),
			SgFrom:    types.StringValue(sgRule.GetSgFrom()),
			SgTo:      types.StringValue(sgRule.GetSgTo()),
			Logs:      types.BoolValue(sgRule.GetLogs()),
			Ports:     portsList,
			Action:    types.StringValue(sgRule.GetAction().String()),
		}
		k := it.Key().String()
		if _, ok := state.Items[k]; ok {
			newState.Items[k] = it
		}
	}
	return newState, diags
}
