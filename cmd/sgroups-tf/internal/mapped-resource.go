package internal

import (
	"context"
	sgroupsAPI "github.com/H-BF/protos/pkg/api/sgroups"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

type anyConstructorWithKey[T any] func(key string, raw any) (string, *T, error)

type mappedRcCRUD[T any] struct {
	tf2proto   anyConstructorWithKey[T]
	labelItems string
	client     SGClient
}

func (c mappedRcCRUD[T]) create(ctx context.Context, rd *schema.ResourceData) error {
	items, _ := rd.Get(c.labelItems).(map[string]any)
	var h listedResource[T]
	h.init("", ";")
	if err := h.addMap(items, c.tf2proto); err != nil {
		return err
	}
	if len(items) > len(h.mapped) {
		return errHasItemDups
	}
	if sgs := h.objects(); len(sgs) > 0 {
		req := makeSyncReq(sgroupsAPI.SyncReq_Upsert, sgs)
		if _, err := c.client.Sync(ctx, req); err != nil {
			return err
		}
	}
	rd.SetId(h.id(noneID))
	return nil
}

func (c mappedRcCRUD[T]) delete(ctx context.Context, rd *schema.ResourceData) error {
	items, _ := rd.Get(c.labelItems).(map[string]any)
	var h listedResource[T]
	h.init("", ";")
	if err := h.addMap(items, c.tf2proto); err != nil {
		return err
	}
	if del := h.objects(); len(del) > 0 {
		req := makeSyncReq(sgroupsAPI.SyncReq_Delete, del)
		_, err := c.client.Sync(ctx, req)
		return err
	}
	return nil
}

func (c mappedRcCRUD[T]) update(ctx context.Context, rd *schema.ResourceData) error {
	var h, h1 listedResource[T]
	h.init("", ";")
	h1.init("", ";")
	items, _ := rd.Get(c.labelItems).(map[string]any)
	if err := h1.addMap(items, c.tf2proto); err != nil {
		return err
	}
	if len(items) > len(h1.mapped) {
		return errHasItemDups
	}
	var del []*T
	old, _ := rd.GetChange(c.labelItems)
	if err := h.addMap(old.(map[string]any), c.tf2proto); err != nil {
		return err
	}
	h.walk(func(k string, nw *T) bool {
		if h1.mapped[k] == nil {
			del = append(del, nw)
		}
		return true
	})
	if len(del) > 0 {
		req := makeSyncReq(sgroupsAPI.SyncReq_Delete, del)
		if _, err := c.client.Sync(ctx, req); err != nil {
			return err
		}
	}
	if upd := h1.objects(); len(upd) > 0 {
		req := makeSyncReq(sgroupsAPI.SyncReq_Upsert, upd)
		if _, err := c.client.Sync(ctx, req); err != nil {
			return err
		}
	}
	rd.SetId(h1.id(noneID))
	return nil
}
