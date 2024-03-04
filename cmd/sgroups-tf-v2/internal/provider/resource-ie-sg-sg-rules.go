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

func NewIESgSgRulesResource() resource.Resource {
	d := Description{
		ResourceDescription: "mapped 'proto:sg-local(local_sg)sg(external_sg)traffic' -> 'SG-SG-<IN|E>GRESS' rule resource",
		ItemsDescription:    "<IN|E>GRESS SG -> SG rules",
	}
	return &ieSgSgRulesResource{
		suffix:      "_ie_rules",
		description: d,
		readState:   readIESgSgRules,
	}
}

type (
	ieSgSgRulesResource = CollectionResource[ieSgSgRule, tfIESgSgRules2Backend]

	ieSgSgRule struct {
		Transport types.String `tfsdk:"transport"`
		Traffic   types.String `tfsdk:"traffic"`
		SgLocal   types.String `tfsdk:"sg_local"`
		Sg        types.String `tfsdk:"sg"`
		Ports     types.List   `tfsdk:"ports"`
		Logs      types.Bool   `tfsdk:"logs"`
		Trace     types.Bool   `tfsdk:"trace"`
	}

	ieSgSgRuleKey struct {
		transport string
		sgLocal   string
		sg        string
		traffic   string
	}
)

// String -
func (k ieSgSgRuleKey) String() string {
	return fmt.Sprintf("%s:sg-local(%s)sg(%s)%s",
		k.transport, k.sgLocal, k.sg, k.traffic)
}

// Key -
func (item ieSgSgRule) Key() *ieSgSgRuleKey {
	return &ieSgSgRuleKey{
		transport: item.Transport.ValueString(),
		sgLocal:   item.SgLocal.ValueString(),
		sg:        item.Sg.ValueString(),
		traffic:   item.Traffic.ValueString(),
	}
}

func (i ieSgSgRule) Attributes() map[string]schema.Attribute {
	return map[string]schema.Attribute{
		"transport": schema.StringAttribute{
			Description: "IP-L4 proto <tcp|udp>",
			Required:    true,
			Validators: []validator.String{
				stringvalidator.OneOf("tcp", "udp"),
			},
		},
		"sg_local": schema.StringAttribute{
			Description: "Security Group name of dst/src group when ingress/egress traffic chosen",
			Required:    true,
		},
		"sg": schema.StringAttribute{
			Description: "Security Group name of opposite group to sg_local",
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
	}
}

func (item ieSgSgRule) IsDiffer(ctx context.Context, other ieSgSgRule) bool { //nolint:dupl
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
		item.Traffic.Equal(other.Traffic) &&
		item.SgLocal.Equal(other.SgLocal) &&
		item.Sg.Equal(other.Sg) &&
		item.Logs.Equal(other.Logs) &&
		item.Trace.Equal(other.Trace) &&
		model.AreRulePortsEq(itemModelPorts, otherModelPorts))
}

func readIESgSgRules(ctx context.Context, state NamedResources[ieSgSgRule], client *sgAPI.Client) (NamedResources[ieSgSgRule], diag.Diagnostics) {
	var diags diag.Diagnostics
	newState := NewNamedResources[ieSgSgRule]()
	var resp *protos.SgSgRulesResp
	var err error
	if len(state.Items) > 0 {
		var req protos.FindSgSgRulesReq
		linq.From(state.Items).
			SelectT(func(i linq.KeyValue) string {
				return i.Value.(ieSgSgRule).SgLocal.ValueString()
			}).Distinct().ToSlice(&req.SgLocal)
		linq.From(state.Items).
			SelectT(func(i linq.KeyValue) string {
				return i.Value.(ieSgSgRule).Sg.ValueString()
			}).Distinct().ToSlice(&req.Sg)
		if resp, err = client.FindSgSgRules(ctx, &req); err != nil {
			diags.AddError("read ie-sg-sg rules", err.Error())
			return newState, diags
		}
	}

	for _, rule := range resp.GetRules() {
		it := ieSgSgRule{
			Transport: types.StringValue(strings.ToLower(rule.Transport.String())),
			Traffic:   types.StringValue(strings.ToLower(rule.GetTraffic().String())),
			SgLocal:   types.StringValue(rule.GetSgLocal()),
			Sg:        types.StringValue(rule.GetSg()),
		}
		k := it.Key().String()
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
			newState.Items[k] = it
		}
	}
	return newState, diags
}
