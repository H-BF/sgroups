package provider

import (
	"context"
	"fmt"
	"regexp"
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
	"github.com/pkg/errors"
)

func NewFqdnRulesResource() resource.Resource {
	d := Description{
		ResourceDescription: "mapped 'proto:sg(SG_FROM)fqdn(FQDN_RECORD_TO)' -> 'SG-FQDN' rule resource",
		ItemsDescription:    "SG -> FQDN rules",
	}
	return &fqdnRulesResource{
		suffix:       "_fqdn_rules",
		description:  d,
		toSubjOfSync: sgFqdnRules2SyncSubj,
		read:         readFqdnRules,
	}
}

type (
	fqdnRulesResource = CollectionResource[sgFqdnRule, protos.SyncFqdnRules]

	fqdnRulesResourceModel = CollectionResourceModel[sgFqdnRule, protos.SyncFqdnRules]

	sgFqdnRule struct {
		Proto  types.String `tfsdk:"proto"`
		SgFrom types.String `tfsdk:"sg_from"`
		Fqdn   types.String `tfsdk:"fqdn"`
		Ports  types.List   `tfsdk:"ports"`
		Logs   types.Bool   `tfsdk:"logs"`
	}

	sgFqdnRuleKey struct {
		proto  string
		sgFrom string
		fqdnTo string
	}
)

var reSgFqdnKey = regexp.MustCompile(
	`^([[:lower:]]+):sg\((\S(?:.*\S)*)\)fqdn\(([[:lower:]-_\d]+(?:\.[[:lower:]-_\d]+)*)\)$`,
)

// FromString -
func (k *sgFqdnRuleKey) FromString(s string) error {
	sm := reSgFqdnKey.FindStringSubmatch(s)
	if len(sm) < 4 { //nolint:gomnd
		return errors.Errorf("bad sg-fqdn rule key (%s)", s)
	}
	k.proto = sm[1]
	k.sgFrom = sm[2]
	k.fqdnTo = sm[3]
	return nil
}

// String -
func (k sgFqdnRuleKey) String() string {
	return fmt.Sprintf("%s:sg(%s)fqdn(%s)",
		strings.ToLower(k.proto), k.sgFrom,
		strings.ToLower(k.fqdnTo))
}

// Key -
func (item sgFqdnRule) Key() *sgFqdnRuleKey {
	return &sgFqdnRuleKey{
		proto:  item.Proto.ValueString(),
		sgFrom: item.SgFrom.ValueString(),
		fqdnTo: item.Fqdn.ValueString(),
	}
}

func (item sgFqdnRule) ResourceAttributes() map[string]schema.Attribute { //nolint:dupl
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
			Description: "Security Group from",
			Required:    true,
		},
		"fqdn": schema.StringAttribute{
			Description: "FQDN",
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

func (item sgFqdnRule) IsDiffer(ctx context.Context, other sgFqdnRule) bool {
	var (
		itemModelPorts, otherModelPorts []model.SGRulePorts
		itemAccPorts, otherAccPorts     []AccessPorts
	)

	_ = item.Ports.ElementsAs(ctx, &itemAccPorts, false)
	_ = other.Ports.ElementsAs(ctx, &otherAccPorts, false)

	// `toModelPorts` can not be failed because its validate then created
	itemModelPorts, _ = toModelPorts(itemAccPorts)
	otherModelPorts, _ = toModelPorts(otherAccPorts)

	return !(strings.EqualFold(item.Proto.ValueString(), other.Proto.ValueString()) &&
		item.SgFrom.Equal(other.SgFrom) &&
		model.FQDN(item.Fqdn.ValueString()).
			IsEq(model.FQDN(other.Fqdn.ValueString())) &&
		item.Logs.Equal(other.Logs) &&
		model.AreRulePortsEq(itemModelPorts, otherModelPorts))
}

func portsToProto(data []AccessPorts) []*protos.AccPorts {
	var ret []*protos.AccPorts
	for _, port := range data {
		ret = append(ret, port.toProto())
	}
	return ret
}

func sgFqdnRules2SyncSubj(ctx context.Context, items map[string]sgFqdnRule) (*protos.SyncFqdnRules, diag.Diagnostics) { //nolint:dupl
	syncFqdnRules := new(protos.SyncFqdnRules)
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
		syncFqdnRules.Rules = append(syncFqdnRules.Rules, &protos.FqdnRule{
			SgFrom:    features.SgFrom.ValueString(),
			FQDN:      features.Fqdn.ValueString(),
			Transport: common.Networks_NetIP_Transport(protoValue),
			Logs:      features.Logs.ValueBool(),
			Ports:     portsToProto(accPorts),
		})
	}
	return syncFqdnRules, diags
}

func readFqdnRules(ctx context.Context, state fqdnRulesResourceModel, client *sgAPI.Client) (fqdnRulesResourceModel, diag.Diagnostics) {
	var diags diag.Diagnostics
	newState := fqdnRulesResourceModel{Items: make(map[string]sgFqdnRule)}
	var resp *protos.FqdnRulesResp
	var err error
	if len(state.Items) > 0 {
		var req protos.FindFqdnRulesReq
		linq.From(state.Items).
			Select(func(i interface{}) interface{} {
				return i.(linq.KeyValue).Value.(sgFqdnRule).SgFrom.ValueString()
			}).Distinct().ToSlice(&req.SgFrom)
		if resp, err = client.FindFqdnRules(ctx, &req); err != nil {
			diags.AddError("read sg-fqdn rules", err.Error())
			return newState, diags
		}
	}
	for _, fqdnRule := range resp.GetRules() {
		accPorts := []AccessPorts{}
		for _, p := range fqdnRule.GetPorts() {
			accPorts = append(accPorts, AccessPorts{
				Source:      types.StringValue(p.S),
				Destination: types.StringValue(p.D),
			})
		}
		portsList, d := types.ListValueFrom(ctx, types.ObjectType{AttrTypes: AccessPorts{}.AttrTypes()}, accPorts)
		diags.Append(d...)
		it := sgFqdnRule{
			Proto:  types.StringValue(strings.ToLower(fqdnRule.GetTransport().String())),
			SgFrom: types.StringValue(fqdnRule.GetSgFrom()),
			Fqdn:   types.StringValue(strings.ToLower(fqdnRule.GetFQDN())),
			Logs:   types.BoolValue(fqdnRule.GetLogs()),
			Ports:  portsList,
		}
		k := it.Key().String()
		if _, ok := state.Items[k]; ok {
			newState.Items[k] = it
		}
	}
	return newState, diags
}
