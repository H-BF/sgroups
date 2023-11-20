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
) ([]*protos.SyncReq, diag.Diagnostics) {
	s, diags := toProto(ctx, model.Items)
	if diags.HasError() {
		return nil, diags
	}
	var reqs []*protos.SyncReq
	switch subject := any(s).(type) {
	case *securityGroupSubject:
		reqs = append(reqs,
			&protos.SyncReq{
				SyncOp:  operation,
				Subject: &protos.SyncReq_Groups{Groups: subject.syncGroups},
			},
			&protos.SyncReq{
				SyncOp:  operation,
				Subject: &protos.SyncReq_SgIcmpRules{SgIcmpRules: subject.syncIcmpParams},
			})
	case *protos.SyncNetworks:
		reqs = append(reqs, &protos.SyncReq{
			SyncOp:  operation,
			Subject: &protos.SyncReq_Networks{Networks: subject},
		})
	case *protos.SyncSGRules:
		reqs = append(reqs, &protos.SyncReq{
			SyncOp:  operation,
			Subject: &protos.SyncReq_SgRules{SgRules: subject},
		})
	case *protos.SyncFqdnRules:
		reqs = append(reqs, &protos.SyncReq{
			SyncOp:  operation,
			Subject: &protos.SyncReq_FqdnRules{FqdnRules: subject},
		})
	case *protos.SyncSgSgIcmpRules:
		reqs = append(reqs, &protos.SyncReq{
			SyncOp:  operation,
			Subject: &protos.SyncReq_SgSgIcmpRules{SgSgIcmpRules: subject},
		})
	default:
		panic("unexpected subject")
	}

	return reqs, nil
}
