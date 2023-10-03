package internal

import (
	"bytes"
	"context"
	"crypto/md5" //nolint:gosec
	"encoding/hex"
	"strings"

	sgroupsAPI "github.com/H-BF/protos/pkg/api/sgroups"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/pkg/errors"
)

const noneID = "<none>"

var errHasItemDups = errors.New("found duplicates in 'items'")

type anyConstructor[T any] func(raw any) (string, *T, error)

type listedResource[T any] struct {
	source []string
	mapped map[string]*T
	sep    string
}

func (rk *listedResource[T]) id(defVal string) string {
	buf := bytes.NewBuffer(nil)
	rk.walk(func(k string, obj *T) bool {
		if obj != nil {
			if buf.Len() > 0 {
				_, _ = buf.WriteString(rk.sep)
			}
			_, _ = buf.WriteString(k)
		}
		return true
	})
	if buf.Len() > 0 {
		h := md5.Sum(buf.Bytes()) //nolint:gosec
		return hex.EncodeToString(h[:])
	}
	return defVal
}

func (rk *listedResource[T]) addlist(raw []any, c anyConstructor[T]) error {
	for _, r := range raw {
		k, o, e := c(r)
		if e != nil {
			return e
		}
		_ = rk.add(k, o)
	}
	return nil
}

func (rk *listedResource[T]) set(k string, obj *T) bool {
	k = strings.TrimSpace(k)
	_, occupied := rk.mapped[k]
	if occupied {
		rk.mapped[k] = obj
	}
	return occupied
}

func (rk *listedResource[T]) add(k string, obj *T) bool {
	k = strings.TrimSpace(k)
	_, occupied := rk.mapped[k]
	if !occupied {
		rk.mapped[k] = obj
		rk.source = append(rk.source, k)
	}
	return !occupied
}

func (rk *listedResource[T]) init(keys string, sep string) {
	rk.sep = sep
	sp := strings.Split(keys, sep)
	rk.source = rk.source[:0]
	rk.mapped = make(map[string]*T)
	for _, s := range sp {
		if s = strings.TrimSpace(s); len(s) > 0 {
			if _, ok := rk.mapped[s]; ok {
				continue
			}
			rk.source = append(rk.source, s)
			rk.mapped[s] = nil
		}
	}
}

func (rk *listedResource[T]) walk(f func(k string, obj *T) bool) {
	for _, k := range rk.source {
		if !f(k, rk.mapped[k]) {
			break
		}
	}
}

func (rk *listedResource[T]) objects() []*T {
	var ret []*T
	rk.walk(func(_ string, obj *T) bool {
		if obj != nil {
			ret = append(ret, obj)
		}
		return true
	})
	return ret
}

func makeSyncReq[T any](op sgroupsAPI.SyncReq_SyncOp, arg []*T) *sgroupsAPI.SyncReq {
	ret := &sgroupsAPI.SyncReq{SyncOp: op}
	switch v := any(arg).(type) {
	case []*sgroupsAPI.Rule:
		ret.Subject = &sgroupsAPI.SyncReq_SgRules{
			SgRules: &sgroupsAPI.SyncSGRules{Rules: v},
		}
	case []*sgroupsAPI.SecGroup:
		ret.Subject = &sgroupsAPI.SyncReq_Groups{
			Groups: &sgroupsAPI.SyncSecurityGroups{Groups: v},
		}
	case []*sgroupsAPI.Network:
		ret.Subject = &sgroupsAPI.SyncReq_Networks{
			Networks: &sgroupsAPI.SyncNetworks{Networks: v},
		}
	case []*sgroupsAPI.FqdnRule:
		ret.Subject = &sgroupsAPI.SyncReq_FqdnRules{
			FqdnRules: &sgroupsAPI.SyncFqdnRules{Rules: v},
		}
	default:
		panic("UB")
	}
	return ret
}

type listedRcCRUD[T any] struct {
	tf2proto   anyConstructor[T]
	labelItems string
	client     SGClient
}

func (c listedRcCRUD[T]) create(ctx context.Context, rd *schema.ResourceData) error {
	items, _ := rd.Get(c.labelItems).([]any)
	var h listedResource[T]
	h.init("", ";")
	if err := h.addlist(items, c.tf2proto); err != nil {
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

func (c listedRcCRUD[T]) delete(ctx context.Context, rd *schema.ResourceData) error {
	items, _ := rd.Get(c.labelItems).([]any)
	var h listedResource[T]
	h.init("", ";")
	if err := h.addlist(items, c.tf2proto); err != nil {
		return err
	}
	if del := h.objects(); len(del) > 0 {
		req := makeSyncReq(sgroupsAPI.SyncReq_Delete, del)
		_, err := c.client.Sync(ctx, req)
		return err
	}
	return nil
}

func (c listedRcCRUD[T]) update(ctx context.Context, rd *schema.ResourceData) error {
	var h, h1 listedResource[T]
	h.init("", ";")
	h1.init("", ";")
	items, _ := rd.Get(c.labelItems).([]any)
	if err := h1.addlist(items, c.tf2proto); err != nil {
		return err
	}
	if len(items) > len(h1.mapped) {
		return errHasItemDups
	}
	var del []*T
	old, _ := rd.GetChange(c.labelItems)
	if err := h.addlist(old.([]any), c.tf2proto); err != nil {
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

//func (c listedRcCRUD[T]) read(_ context.Context, _ *schema.ResourceData) error {
//	panic("do not use it")
//}
