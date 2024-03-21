package provider

import (
	"context"
	"fmt"
	"strings"

	"github.com/H-BF/sgroups/cmd/sgroups-tf-v2/internal/validators"
	sgAPI "github.com/H-BF/sgroups/internal/api/sgroups"
	model "github.com/H-BF/sgroups/internal/models/sgroups"

	protos "github.com/H-BF/protos/pkg/api/sgroups"
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

func NewCidrRulesResource() resource.Resource {
	d := Description{
		ResourceDescription: "mapped 'proto:cidr(CIDR)sg(SG_NAME)traffic' -> 'CIDR-SG' rule resource",
		ItemsDescription:    "CIDR-SG rules",
	}
	return &cidrRulesResource{
		suffix:      "_cidr_rules",
		description: d,
		readState:   readCidrRules,
	}
}

type (
	cidrRulesResource = CollectionResource[cidrRule, tfCidrSgRules2Backend]

	cidrRule struct {
		Transport types.String `tfsdk:"transport"`
		Cidr      types.String `tfsdk:"cidr"`
		SgName    types.String `tfsdk:"sg_name"`
		Traffic   types.String `tfsdk:"traffic"`
		Ports     types.List   `tfsdk:"ports"`
		Logs      types.Bool   `tfsdk:"logs"`
		Trace     types.Bool   `tfsdk:"trace"`
		Action    types.String `tfsdk:"action"`
	}

	cidrRuleKey struct {
		transport string
		cidr      string
		sgName    string
		traffic   string
	}
)

func (k cidrRuleKey) String() string {
	return fmt.Sprintf("%s:cidr(%s)sg(%s)%s",
		strings.ToLower(k.transport), k.cidr, k.sgName,
		strings.ToLower(k.traffic))
}

func (item cidrRule) Key() *cidrRuleKey {
	return &cidrRuleKey{
		transport: item.Transport.ValueString(),
		cidr:      item.Cidr.ValueString(),
		sgName:    item.SgName.ValueString(),
		traffic:   item.Traffic.ValueString(),
	}
}

func (item cidrRule) Attributes() map[string]schema.Attribute {
	return map[string]schema.Attribute{
		"transport": schema.StringAttribute{
			Description: "IP-L4 proto <tcp|udp>",
			Required:    true,
			Validators: []validator.String{
				stringvalidator.OneOf("tcp", "udp"),
			},
		},
		"cidr": schema.StringAttribute{
			Description: "IP subnet",
			Required:    true,
			Validators: []validator.String{
				validators.IsCIDR(),
			},
		},
		"sg_name": schema.StringAttribute{
			Description: "Security Group name",
			Required:    true,
		},
		"traffic": schema.StringAttribute{
			Description: "direction of traffic <ingress|egress>",
			Required:    true,
			Validators: []validator.String{
				stringvalidator.OneOf("ingress", "egress"),
			},
		},
		"ports": schema.ListNestedAttribute{
			Description: "access ports",
			Optional:    true,
			NestedObject: schema.NestedAttributeObject{
				Attributes: AccessPorts{}.Attributes(),
			},
			PlanModifiers: []planmodifier.List{ListAccessPortsModifier()},
		},
		"logs": schema.BoolAttribute{
			Description: "toggle logging on every rule in security group",
			Optional:    true,
			Computed:    true,
			Default:     booldefault.StaticBool(false),
		},
		"trace": schema.BoolAttribute{
			Description: "toggle tracing on every rule in security group",
			Optional:    true,
			Computed:    true,
			Default:     booldefault.StaticBool(false),
		},
		"action": schema.StringAttribute{
			Description: "Rule action on packets in chain",
			Required:    true,
			Validators:  []validator.String{actionValidator},
		},
	}
}

func (item cidrRule) IsDiffer(ctx context.Context, other cidrRule) bool {
	var (
		itemModelPorts, otherModelPorts []model.SGRulePorts
		itemAccPorts, otherAccPorts     []AccessPorts
	)

	_ = item.Ports.ElementsAs(ctx, &itemAccPorts, false)
	_ = other.Ports.ElementsAs(ctx, &otherAccPorts, false)

	// `toModelPorts` can not be failed because its validate then created
	itemModelPorts, _ = toModelPorts(itemAccPorts)
	otherModelPorts, _ = toModelPorts(otherAccPorts)

	return !(item.Transport.Equal(other.Transport) &&
		item.Cidr.Equal(other.Cidr) &&
		item.SgName.Equal(other.SgName) &&
		item.Traffic.Equal(other.Traffic) &&
		item.Logs.Equal(other.Logs) &&
		item.Trace.Equal(other.Trace) &&
		item.Action.Equal(other.Action) &&
		model.AreRulePortsEq(itemModelPorts, otherModelPorts))
}

func readCidrRules(ctx context.Context, state NamedResources[cidrRule], client *sgAPI.Client) (NamedResources[cidrRule], diag.Diagnostics) {
	var diags diag.Diagnostics
	newState := NewNamedResources[cidrRule]()
	var resp *protos.CidrSgRulesResp
	var err error
	if len(state.Items) > 0 {
		var req protos.FindCidrSgRulesReq
		linq.From(state.Items).
			SelectT(func(i linq.KeyValue) string {
				return i.Value.(cidrRule).SgName.ValueString()
			}).Distinct().ToSlice(&req.Sg)
		if resp, err = client.FindCidrSgRules(ctx, &req); err != nil {
			diags.AddError("read cidr-sg rules", err.Error())
			return newState, diags
		}
	}
	for _, rule := range resp.GetRules() {
		it := cidrRule{
			Transport: types.StringValue(strings.ToLower(rule.Transport.String())),
			Cidr:      types.StringValue(rule.GetCIDR()),
			SgName:    types.StringValue(rule.GetSG()),
			Traffic:   types.StringValue(strings.ToLower(rule.GetTraffic().String())),
		}
		k := it.Key().String()           //nolint:dupl
		if _, ok := state.Items[k]; ok { //nolint:dupl
			accPorts := []AccessPorts{}
			for _, p := range rule.GetPorts() {
				accPorts = append(accPorts, AccessPorts{
					Source:      types.StringValue(p.S),
					Destination: types.StringValue(p.D),
				})
			}
			portsList, d := types.ListValueFrom(ctx, types.ObjectType{AttrTypes: AccessPorts{}.AttrTypes()}, accPorts)
			diags.Append(d...)
			it.Ports = portsList
			it.Logs = types.BoolValue(rule.GetLogs())
			it.Trace = types.BoolValue(rule.GetTrace())
			it.Action = types.StringValue(rule.GetAction().String())
			newState.Items[k] = it
		}
	}
	return newState, diags
}
