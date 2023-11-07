package provider

import (
	"context"

	protos "github.com/H-BF/protos/pkg/api/sgroups"
	"github.com/hashicorp/terraform-plugin-framework/diag"
)

type (
	CollectionResourceModel[T any, S subjectOfSync] struct {
		Items map[string]T `tfsdk:"items"`
	}
)

func (model *CollectionResourceModel[T, S]) toSyncReq(
	ctx context.Context, operation protos.SyncReq_SyncOp,
	toProto func(context.Context, map[string]T) (*S, diag.Diagnostics),
) (*protos.SyncReq, diag.Diagnostics) {
	req := &protos.SyncReq{SyncOp: operation}

	s, diags := toProto(ctx, model.Items)
	if diags.HasError() {
		return nil, diags
	}
	switch subject := any(s).(type) {
	case *protos.SyncNetworks:
		req.Subject = &protos.SyncReq_Networks{Networks: subject}
	case *protos.SyncSecurityGroups:
		req.Subject = &protos.SyncReq_Groups{Groups: subject}
	case *protos.SyncSGRules:
		req.Subject = &protos.SyncReq_SgRules{SgRules: subject}
	case *protos.SyncFqdnRules:
		req.Subject = &protos.SyncReq_FqdnRules{FqdnRules: subject}
	default:
		panic("unexpected subject")
	}

	return req, nil
}
