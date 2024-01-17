package provider

import (
	"context"
	"fmt"
	"strings"

	sgAPI "github.com/H-BF/sgroups/internal/api/sgroups"
	"github.com/H-BF/sgroups/internal/dict"

	"github.com/H-BF/protos/pkg/api/common"
	protos "github.com/H-BF/protos/pkg/api/sgroups"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

type tf2backend[T SingleResource[T]] interface {
	sync(context.Context, NamedResources[T], *sgAPI.Client, protos.SyncReq_SyncOp) diag.Diagnostics
}

type (
	tfNetworks2Backend      struct{}
	tfSg2Backend            struct{}
	tfSgSgRules2Backend     struct{}
	tfSgSgIcmpRules2Backend struct{}
	tfSgFqdnRules2Backend   struct{}
	tfCidrSgRules2Backend   struct{}
)

var (
	_ tf2backend[networkItem]  = (*tfNetworks2Backend)(nil)
	_ tf2backend[sgItem]       = (*tfSg2Backend)(nil)
	_ tf2backend[sgSgRule]     = (*tfSgSgRules2Backend)(nil)
	_ tf2backend[sgSgIcmpRule] = (*tfSgSgIcmpRules2Backend)(nil)
	_ tf2backend[sgFqdnRule]   = (*tfSgFqdnRules2Backend)(nil)
	_ tf2backend[cidrRule]     = (*tfCidrSgRules2Backend)(nil)

	_ = tfNetworks2Backend.sync
	_ = tfSg2Backend.sync
	_ = tfSgSgRules2Backend.sync
	_ = tfSgSgIcmpRules2Backend.sync
	_ = tfSgFqdnRules2Backend.sync
	_ = tfCidrSgRules2Backend.sync
)

func (tfNetworks2Backend) sync(ctx context.Context, items NamedResources[networkItem], client *sgAPI.Client, op protos.SyncReq_SyncOp) diag.Diagnostics {
	var sn protos.SyncNetworks
	var diags diag.Diagnostics
	for _, netFeatures := range items.Items {
		sn.Networks = append(sn.Networks, &protos.Network{
			Name:    netFeatures.Name.ValueString(),
			Network: &common.Networks_NetIP{CIDR: netFeatures.Cidr.ValueString()},
		})
	}
	req := protos.SyncReq{
		SyncOp:  op,
		Subject: &protos.SyncReq_Networks{Networks: &sn},
	}
	if _, err := client.Sync(ctx, &req); err != nil {
		diags.AddError(
			fmt.Sprintf("%s(networks)", op),
			err.Error(),
		)
	}
	return diags
}

func (tfSg2Backend) sync(ctx context.Context, items NamedResources[sgItem], client *sgAPI.Client, op protos.SyncReq_SyncOp) diag.Diagnostics { //nolint:gocyclo
	var diags diag.Diagnostics
	var icmp dict.HDict[string, types.Object]
	var icmp6 dict.HDict[string, types.Object]
	var sgIcmp2Del protos.SyncSgIcmpRules
	var sgIcmp2Upd protos.SyncSgIcmpRules
	var syncSgs protos.SyncSecurityGroups
	for _, item := range items.Items {
		sg := protos.SecGroup{
			Name: item.Name.ValueString(),
		}
		if op != protos.SyncReq_Delete {
			if !item.Icmp.IsUnknown() {
				icmp.Insert(item.Name.ValueString(), item.Icmp)
			}
			if !item.Icmp6.IsUnknown() {
				icmp6.Insert(item.Name.ValueString(), item.Icmp6)
			}
			diags.Append(item.Networks.ElementsAs(ctx, &sg.Networks, true)...)
			if diags.HasError() {
				return diags
			}
			da := item.DefaultAction.ValueString()
			sg.DefaultAction = protos.SecGroup_DefaultAction(protos.SecGroup_DefaultAction_value[da])
			sg.Trace = item.Trace.ValueBool()
			sg.Logs = item.Logs.ValueBool()
		}
		syncSgs.Groups = append(syncSgs.Groups, &sg)
	}

	// delete/update ICMP(s)
	ipf := []common.IpAddrFamily{common.IpAddrFamily_IPv4, common.IpAddrFamily_IPv6}
	icmps := []*dict.HDict[string, types.Object]{&icmp, &icmp6}
	for i := range ipf {
		icmps[i].Iterate(func(sgName string, o types.Object) bool {
			rule := &protos.SgIcmpRule{
				Sg:   sgName,
				ICMP: &common.ICMP{IPv: ipf[i]},
			}
			if o.IsNull() {
				sgIcmp2Del.Rules = append(sgIcmp2Del.Rules, rule)
				return true
			}
			sgIcmp2Upd.Rules = append(sgIcmp2Upd.Rules, rule)
			var icmpParams IcmpParameters
			diags.Append(
				o.As(ctx, &icmpParams, basetypes.ObjectAsOptions{UnhandledUnknownAsEmpty: true})...,
			)
			if !diags.HasError() {
				rule.Logs = icmpParams.Logs.ValueBool()
				rule.Trace = icmpParams.Trace.ValueBool()
				diags.Append(
					icmpParams.Type.ElementsAs(ctx, &rule.ICMP.Types, true)...,
				)
			}
			return !diags.HasError()
		})
		if diags.HasError() {
			return diags
		}
	}
	if len(sgIcmp2Del.Rules) > 0 {
		req := protos.SyncReq{
			SyncOp: protos.SyncReq_Delete,
			Subject: &protos.SyncReq_SgIcmpRules{
				SgIcmpRules: &sgIcmp2Del,
			},
		}
		if _, err := client.Sync(ctx, &req); err != nil {
			diags.AddError(
				fmt.Sprintf("%s(sg-icmp-rules)", protos.SyncReq_Delete),
				err.Error(),
			)
		}
	}
	if !diags.HasError() && len(syncSgs.Groups) > 0 {
		req := protos.SyncReq{
			SyncOp: op,
			Subject: &protos.SyncReq_Groups{
				Groups: &syncSgs,
			},
		}
		if _, err := client.Sync(ctx, &req); err != nil {
			diags.AddError(
				fmt.Sprintf("%s(security-groups)", op),
				err.Error(),
			)
		}
	}
	if !diags.HasError() && len(sgIcmp2Upd.Rules) > 0 {
		req := protos.SyncReq{
			SyncOp: protos.SyncReq_Upsert,
			Subject: &protos.SyncReq_SgIcmpRules{
				SgIcmpRules: &sgIcmp2Upd,
			},
		}
		if _, err := client.Sync(ctx, &req); err != nil {
			diags.AddError(
				fmt.Sprintf("%s(sg-icmp-rules)", protos.SyncReq_Upsert),
				err.Error(),
			)
		}
	}
	return diags
}

func (tfSgSgRules2Backend) sync(ctx context.Context, items NamedResources[sgSgRule], client *sgAPI.Client, op protos.SyncReq_SyncOp) diag.Diagnostics { //nolint:dupl
	var syncObj protos.SyncSGRules
	var diags diag.Diagnostics
	for _, features := range items.Items {
		var accPorts []AccessPorts
		diags.Append(features.Ports.ElementsAs(ctx, &accPorts, false)...)
		if diags.HasError() {
			return diags
		}
		// this conversion necessary to validate string with ports
		if _, err := toModelPorts(accPorts); err != nil {
			diags.AddError("ports conv", err.Error())
			return diags
		}
		protoValue, ok := common.Networks_NetIP_Transport_value[strings.ToUpper(
			features.Proto.ValueString(),
		)]
		if !ok {
			diags.AddError(
				"proto conv",
				fmt.Sprintf("no proto conv for value(%s)", features.Proto.ValueString()))
			return diags
		}
		syncObj.Rules = append(syncObj.Rules, &protos.Rule{
			SgFrom:    features.SgFrom.ValueString(),
			SgTo:      features.SgTo.ValueString(),
			Transport: common.Networks_NetIP_Transport(protoValue),
			Logs:      features.Logs.ValueBool(),
			Ports:     portsToProto(accPorts),
		})
	}
	req := protos.SyncReq{
		SyncOp: op,
		Subject: &protos.SyncReq_SgRules{
			SgRules: &syncObj,
		},
	}
	if _, err := client.Sync(ctx, &req); err != nil {
		diags.AddError(
			fmt.Sprintf("%s(sg-sh-rules)", op),
			err.Error(),
		)
	}
	return diags
}

func (tfSgSgIcmpRules2Backend) sync(ctx context.Context, items NamedResources[sgSgIcmpRule], client *sgAPI.Client, op protos.SyncReq_SyncOp) diag.Diagnostics {
	var syncObj protos.SyncSgSgIcmpRules
	var diags diag.Diagnostics
	for _, features := range items.Items {
		syncObj.Rules = append(syncObj.Rules, &protos.SgSgIcmpRule{
			SgFrom: features.SgFrom.ValueString(),
			SgTo:   features.SgTo.ValueString(),
			ICMP:   features.icmp2Proto(ctx, &diags),
			Logs:   features.Logs.ValueBool(),
			Trace:  features.Trace.ValueBool(),
		})
		if diags.HasError() {
			return diags
		}
	}
	req := protos.SyncReq{
		SyncOp: op,
		Subject: &protos.SyncReq_SgSgIcmpRules{
			SgSgIcmpRules: &syncObj,
		},
	}
	if _, err := client.Sync(ctx, &req); err != nil {
		diags.AddError(
			fmt.Sprintf("%s(sg-sg-icmp-rules)", op), err.Error(),
		)
	}
	return diags
}

func (tfSgFqdnRules2Backend) sync(ctx context.Context, items NamedResources[sgFqdnRule], client *sgAPI.Client, op protos.SyncReq_SyncOp) diag.Diagnostics { //nolint:dupl
	var syncFqdnRules protos.SyncFqdnRules
	var diags diag.Diagnostics
	for _, features := range items.Items {
		var accPorts []AccessPorts
		diags.Append(features.Ports.ElementsAs(ctx, &accPorts, false)...)
		if diags.HasError() {
			return diags
		}
		// this conversion necessary to validate string with ports
		if _, err := toModelPorts(accPorts); err != nil {
			diags.AddError("ports conv", err.Error())
			return diags
		}
		transportValue, ok := common.Networks_NetIP_Transport_value[strings.ToUpper(
			features.Proto.ValueString(),
		)]
		if !ok {
			diags.AddError(
				"proto conv",
				fmt.Sprintf("no proto conv for value(%s)", features.Proto.ValueString()))
			return diags
		}
		var protocols []string
		diags.Append(features.Protocols.ElementsAs(ctx, &protocols, false)...)
		if diags.HasError() {
			return diags
		}
		syncFqdnRules.Rules = append(syncFqdnRules.Rules, &protos.FqdnRule{
			SgFrom:    features.SgFrom.ValueString(),
			FQDN:      features.Fqdn.ValueString(),
			Transport: common.Networks_NetIP_Transport(transportValue),
			Logs:      features.Logs.ValueBool(),
			Ports:     portsToProto(accPorts),
			Protocols: protocols,
		})
	}
	req := protos.SyncReq{
		SyncOp: op,
		Subject: &protos.SyncReq_FqdnRules{
			FqdnRules: &syncFqdnRules,
		},
	}
	if _, err := client.Sync(ctx, &req); err != nil {
		diags.AddError(
			fmt.Sprintf("%s(sg-fqdn-rules)", op), err.Error(),
		)
	}
	return diags
}

func (tfCidrSgRules2Backend) sync(ctx context.Context, items NamedResources[cidrRule], client *sgAPI.Client, op protos.SyncReq_SyncOp) diag.Diagnostics {
	var syncCidrRules protos.SyncCidrSgRules
	var diags diag.Diagnostics
	for _, features := range items.Items {
		var accPorts []AccessPorts
		diags.Append(features.Ports.ElementsAs(ctx, &accPorts, false)...)
		if diags.HasError() {
			return diags
		}
		// this conversion necessary to validate string with ports
		if _, err := toModelPorts(accPorts); err != nil {
			diags.AddError("ports conv", err.Error())
			return diags
		}
		protoValue, ok := common.Networks_NetIP_Transport_value[strings.ToUpper(
			features.Proto.ValueString(),
		)]
		if !ok {
			diags.AddError(
				"proto conv",
				fmt.Sprintf("no proto conv for value(%s)", features.Proto.ValueString()))
			return diags
		}
		caser := cases.Title(language.AmericanEnglish).String
		trafficValue, ok := common.Traffic_value[caser(
			features.Traffic.ValueString(),
		)]
		if !ok {
			diags.AddError(
				"traffic conv",
				fmt.Sprintf("no traffic conv for value(%s)", features.Traffic.ValueString()))
			return diags
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
	req := protos.SyncReq{
		SyncOp: op,
		Subject: &protos.SyncReq_CidrSgRules{
			CidrSgRules: &syncCidrRules,
		},
	}
	if _, err := client.Sync(ctx, &req); err != nil {
		diags.AddError(
			fmt.Sprintf("%s(cidr-sg-rules)", op), err.Error(),
		)
	}
	return diags
}
