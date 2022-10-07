package sgroups

import (
	"context"
	"reflect"

	model "github.com/H-BF/sgroups/internal/models/sgroups"
	"github.com/hashicorp/go-memdb"
	"github.com/pkg/errors"
)

var (
	_ = sGroupsMemDbWriter{}
)

type sGroupsMemDbWriter struct {
	writer MemDbWriter
}

//SyncNetworks impl Writer = update / delete networks
func (wr sGroupsMemDbWriter) SyncNetworks(_ context.Context, networks []model.Network, scope Scope, opts ...Option) error {
	const api = "mem-db/SyncNetworks"
	var err error
	var h diffHelper[model.Network, string]
	if err = h.init(networks, nil); err != nil {
		return errors.WithMessage(err, api)
	}
	var it MemDbIterator
	if it, err = wr.writer.Get(TblNetworks, indexID, scope); err != nil {
		return errors.WithMessage(err, api)
	}
	for v := it.Next(); v != nil; v = it.Next() {
		if err = h.addNew(*v.(*model.Network)); err != nil {
			return errors.WithMessage(err, api)
		}
	}
	upd, ins, del := h.diff(opts...)
	for _, obj := range append(upd, ins...) {
		if err = wr.writer.Upsert(TblNetworks, obj); err != nil {
			return errors.WithMessage(err, api)
		}
	}
	for _, obj := range del {
		err = wr.writer.Delete(TblNetworks, obj)
		if err != nil && !errors.Is(err, memdb.ErrNotFound) {
			break
		}
		if err = wr.onDeleteNetwork(obj); err != nil {
			break
		}
	}
	return errors.WithMessage(err, api)
}

//SyncSecurityGroups impl Writer = update / delete security groups
func (wr sGroupsMemDbWriter) SyncSecurityGroups(ctx context.Context, sgs []model.SecurityGroup, scope Scope, opts ...Option) error {
	return nil
}

//SyncSGRules impl Writer = update / delete security group rules
func (wr sGroupsMemDbWriter) SyncSGRules(ctx context.Context, rules []model.SGRule, scope Scope, opts ...Option) error {
	//var h updateHelper[model.SGRule, string]
	//rules[0].PortsTo.
	return nil
}

func (wr sGroupsMemDbWriter) onDeleteNetwork(nw model.Network) error {
	_ = nw
	return nil
}

type diffHelper[T any, TKey comparable] struct {
	cur map[TKey]T
	new map[TKey]T
}

func (h *diffHelper[T, TKey]) init(newValues, curValues []T) error {
	h.cur = make(map[TKey]T)
	h.new = make(map[TKey]T)
	for _, v := range newValues {
		if e := h.addNew(v); e != nil {
			return e
		}
	}
	for _, v := range curValues {
		if e := h.addCurrent(v); e != nil {
			return e
		}
	}
	return nil
}

func (h diffHelper[T, TKey]) add(v T, toCurrent bool) error {
	k, e := h.extractKey(v)
	if e != nil {
		return e
	}
	if toCurrent {
		h.cur[k] = v
	} else {
		h.new[k] = v
	}
	return nil
}

func (h diffHelper[T, TKey]) addNew(v T) error {
	return h.add(v, false)
}

func (h diffHelper[T, TKey]) addCurrent(v T) error {
	return h.add(v, true)
}

func (h diffHelper[T, TKey]) diff(opts ...Option) (upd, ins, del []T) {
	i, u, d := true, true, true
	for n := range opts {
		switch opts[n].(type) {
		case SyncOmitInsert:
			i = false
		case SyncOmitUpdate:
			u = false
		case SyncOmitDelete:
			d = false
		}
	}
	if i || u {
		for keyNew, vNew := range h.new {
			if vCur, ok := h.cur[keyNew]; !ok && i {
				ins = append(ins, vNew)
			} else if ok && u && !h.isEQ(vNew, vCur) {
				upd = append(upd, vNew)
			}
		}
	}
	if d {
		for keyCur, vCur := range h.cur {
			if _, found := h.cur[keyCur]; !found {
				del = append(del, vCur)
			}
		}
	}
	return
}

func (h diffHelper[T, TKey]) extractKey(obj T) (TKey, error) {
	var k TKey
	var vSrc reflect.Value
	switch a := interface{}(obj).(type) {
	case model.Network:
		vSrc = reflect.ValueOf(a.Name)
	case model.SecurityGroup:
		vSrc = reflect.ValueOf(a.Name)
	case model.SGRule:
		vSrc = reflect.ValueOf(a.IdentityHash())
	default:
		return k, errors.Errorf("key-extractor: no extraction from '%T' type", obj)
	}
	vDest := reflect.ValueOf(&k).Elem()
	if !vDest.Type().ConvertibleTo(vSrc.Type()) {
		return k, errors.Errorf("key-extractor: unable convert from '%T' to '%T'",
			obj, k)
	}
	vDest.Set(vSrc.Convert(vDest.Type()))
	return k, nil
}

func (h diffHelper[T, TKey]) isEQ(l, r T) bool {
	return false
}
