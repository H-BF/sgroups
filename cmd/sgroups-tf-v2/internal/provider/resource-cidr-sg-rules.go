package provider

import (
	"context"
	"fmt"
	"strings"

	"github.com/H-BF/sgroups/cmd/sgroups-tf-v2/internal/validators"
	sgAPI "github.com/H-BF/sgroups/internal/api/sgroups"
	model "github.com/H-BF/sgroups/internal/models/sgroups"

	"github.com/H-BF/protos/pkg/api/common"
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
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

func NewCidrRulesResource() resource.Resource {
	d := Description{
		ResourceDescription: "mapped 'proto:cidr(CIDR)sg(SG_NAME)traffic' -> 'CIDR-SG' rule resource",
		ItemsDescription:    "CIDR-SG rules",
	}
	return &cidrRulesResource{
		suffix:       "_cidr_rules",
		description:  d,
		toSubjOfSync: cidrRules2SyncSubj,
		read:         readCidrRules,
	}
}

type (
	cidrRulesResource = CollectionResource[cidrRule, protos.SyncCidrSgRules]

	cidrRulesResourceModel = CollectionResourceModel[cidrRule, protos.SyncCidrSgRules]

	cidrRule struct {
		Proto   types.String `tfsdk:"proto"`
		Cidr    types.String `tfsdk:"cidr"`
		SgName  types.String `tfsdk:"sg_name"`
		Traffic types.String `tfsdk:"traffic"`
		Ports   types.List   `tfsdk:"ports"`
		Logs    types.Bool   `tfsdk:"logs"`
		Trace   types.Bool   `tfsdk:"trace"`
	}

	cidrRuleKey struct {
		proto   string
		cidr    string
		sgName  string
		traffic string
	}
)

func (k cidrRuleKey) String() string {
	return fmt.Sprintf("%s:cidr(%s)sg(%s)%s",
		strings.ToLower(k.proto), k.cidr, k.sgName,
		strings.ToLower(k.traffic))
}

func (item cidrRule) Key() *cidrRuleKey {
	return &cidrRuleKey{
		proto:   item.Proto.ValueString(),
		cidr:    item.Cidr.ValueString(),
		sgName:  item.SgName.ValueString(),
		traffic: item.Traffic.ValueString(),
	}
}

func (item cidrRule) ResourceAttributes() map[string]schema.Attribute {
	return map[string]schema.Attribute{
		"proto": schema.StringAttribute{
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
				Attributes: AccessPorts{}.ResourceAttributes(),
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

	return !(item.Proto.Equal(other.Proto) &&
		item.Cidr.Equal(other.Cidr) &&
		item.SgName.Equal(other.SgName) &&
		item.Traffic.Equal(other.Traffic) &&
		item.Logs.Equal(other.Logs) &&
		item.Trace.Equal(other.Trace) &&
		model.AreRulePortsEq(itemModelPorts, otherModelPorts))
}

func cidrRules2SyncSubj(ctx context.Context, items map[string]cidrRule) (*protos.SyncCidrSgRules, diag.Diagnostics) {
	syncCidrRules := new(protos.SyncCidrSgRules)
	var diags diag.Diagnostics
	for _, features := range items {
		var accPorts []AccessPorts
		diags.Append(features.Ports.ElementsAs(ctx, &accPorts, false)...)
		if diags.HasError() {
			return nil, diags
		}
		// this conversion necessary to validate string with ports
		if _, err := toModelPorts(accPorts); err != nil {
			diags.AddError("ports conv", err.Error())
			return nil, diags
		}
		protoValue, ok := common.Networks_NetIP_Transport_value[strings.ToUpper(
			features.Proto.ValueString(),
		)]
		if !ok {
			diags.AddError(
				"proto conv",
				fmt.Sprintf("no proto conv for value(%s)", features.Proto.ValueString()))
			return nil, diags
		}
		caser := cases.Title(language.AmericanEnglish).String
		trafficValue, ok := common.Traffic_value[caser(
			features.Traffic.ValueString(),
		)]
		if !ok {
			diags.AddError(
				"traffic conv",
				fmt.Sprintf("no traffic conv for value(%s)", features.Traffic.ValueString()))
			return nil, diags
		}
		syncCidrRules.Rules = append(syncCidrRules.Rules, &protos.CidrSgRule{
			Transport: common.Networks_NetIP_Transport(protoValue),
			CIDR:      features.Cidr.ValueString(),
			SG:        features.SgName.ValueString(),
			Traffic:   common.Traffic(trafficValue),
			Ports:     portsToProto(accPorts),
			Logs:      features.Logs.ValueBool(),
			Trace:     features.Trace.ValueBool(),
		})
	}
	return syncCidrRules, diags
}

func readCidrRules(ctx context.Context, state cidrRulesResourceModel, client *sgAPI.Client) (cidrRulesResourceModel, diag.Diagnostics) {
	var diags diag.Diagnostics
	newState := cidrRulesResourceModel{Items: make(map[string]cidrRule)}
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
			Proto:   types.StringValue(strings.ToLower(rule.Transport.String())),
			Cidr:    types.StringValue(rule.GetCIDR()),
			SgName:  types.StringValue(rule.GetSG()),
			Traffic: types.StringValue(strings.ToLower(rule.GetTraffic().String())),
		}
		k := it.Key().String()
		if _, ok := state.Items[k]; ok {
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
