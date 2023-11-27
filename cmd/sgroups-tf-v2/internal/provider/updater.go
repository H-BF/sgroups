package provider

import (
	"context"

	protos "github.com/H-BF/protos/pkg/api/sgroups"

	"github.com/hashicorp/terraform-plugin-framework/diag"
)

type (
	ResourceUpdater[T SingleResource[T], S subjectOfSync] interface {
		deleteRequests(ctx context.Context, stateItems map[string]T, planItems map[string]T) ([]*protos.SyncReq, diag.Diagnostics)
		updateRequests(ctx context.Context, stateItems map[string]T, planItems map[string]T) ([]*protos.SyncReq, diag.Diagnostics)
		deleteEmbedReqs(ctx context.Context, stateItems map[string]T, planItems map[string]T) ([]*protos.SyncReq, diag.Diagnostics)
	}

	baseUpdater[T SingleResource[T], S subjectOfSync] struct {
		toSubjOfSync func(context.Context, map[string]T) (*S, diag.Diagnostics)
	}
)

func (u baseUpdater[T, S]) deleteRequests(ctx context.Context, stateItems map[string]T, planItems map[string]T) ([]*protos.SyncReq, diag.Diagnostics) { //nolint:lll
	var (
		res   []*protos.SyncReq
		diags diag.Diagnostics
	)

	itemsToDelete := map[string]T{}
	for name, itemFeatures := range stateItems {
		if _, ok := planItems[name]; !ok {
			// if item is missing in plan state - delete it
			itemsToDelete[name] = itemFeatures
		}
	}

	if len(itemsToDelete) > 0 {
		tempModel := CollectionResourceModel[T, S]{
			Items: itemsToDelete,
		}
		res, diags = tempModel.toSyncReq(ctx, protos.SyncReq_Delete, u.toSubjOfSync)
		if diags.HasError() {
			return nil, diags
		}
	}
	return res, nil
}

func (u baseUpdater[T, S]) updateRequests(ctx context.Context, stateItems map[string]T, planItems map[string]T) ([]*protos.SyncReq, diag.Diagnostics) { //nolint:lll
	var (
		res   []*protos.SyncReq
		diags diag.Diagnostics
	)

	itemsToUpdate := map[string]T{}
	for name, itemFeatures := range planItems {
		// in plan state can have unchanged items which should be ignored
		// missing items before and changed items should be updated
		if oldItemFeatures, ok := stateItems[name]; !ok || itemFeatures.IsDiffer(ctx, oldItemFeatures) {
			itemsToUpdate[name] = itemFeatures
		}
	}

	if len(itemsToUpdate) > 0 {
		tempModel := CollectionResourceModel[T, S]{
			Items: itemsToUpdate,
		}
		res, diags = tempModel.toSyncReq(ctx, protos.SyncReq_Upsert, u.toSubjOfSync)
		if diags.HasError() {
			return nil, diags
		}
	}
	return res, nil
}

func (u baseUpdater[T, S]) deleteEmbedReqs(ctx context.Context, stateItems map[string]T, planItems map[string]T) ([]*protos.SyncReq, diag.Diagnostics) { //nolint:lll
	return nil, nil
}

var (
	updater = &baseUpdater[networkItem, protos.SyncNetworks]{}
	_       = updater.deleteRequests
	_       = updater.updateRequests
	_       = updater.deleteEmbedReqs

	_ ResourceUpdater[networkItem, protos.SyncNetworks] = updater
)
