package provider

import (
	protos "github.com/H-BF/protos/pkg/api/sgroups"
	"golang.org/x/exp/maps"
)

type (
	CollectionResourceModel[T any, S protoSubject] struct {
		Items map[string]T `tfsdk:"items"`
	}
)

func (model *CollectionResourceModel[T, S]) asSyncReq(operation protos.SyncReq_SyncOp, toProto func(map[string]T) *S) *protos.SyncReq {
	req := &protos.SyncReq{SyncOp: operation}

	s := toProto(model.Items)
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

	return req
}

func (model *CollectionResourceModel[T, S]) itemsToDelete(priorState *CollectionResourceModel[T, S]) CollectionResourceModel[T, S] {
	itemsToDelete := map[string]T{}
	for name, itemFeatures := range priorState.Items {
		if _, ok := model.Items[name]; !ok {
			itemsToDelete[name] = itemFeatures
		}
	}

	modelToDelete := CollectionResourceModel[T, S]{
		Items: itemsToDelete,
	}
	return modelToDelete
}

func (model *CollectionResourceModel[T, S]) getNames() []string {
	return maps.Keys(model.Items)
}
