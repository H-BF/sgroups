package sgroups

import (
	"bytes"
	"context"
	"net"
	"reflect"
	"time"

	model "github.com/H-BF/sgroups/internal/models/sgroups"
	"github.com/hashicorp/go-memdb"
	"github.com/pkg/errors"
	"go.uber.org/multierr"
)

type sGroupsMemDbWriter struct {
	sGroupsMemDbReader
	writer MemDbWriter
}

// SyncNetworks impl Writer = update / delete networks
func (wr sGroupsMemDbWriter) SyncNetworks(ctx context.Context, networks []model.Network, scope Scope, opts ...Option) error {
	const api = "mem-db/SyncNetworks"

	it, err := wr.writer.Get(TblNetworks, indexID)
	if err != nil {
		return errors.WithMessage(err, api)
	}
	var ft filterTree[model.Network]
	if !ft.init(scope) {
		return errors.Errorf("bad scope")
	}
	it = memdb.NewFilterIterator(it, func(i interface{}) bool {
		nw := *i.(*model.Network)
		return !ft.invoke(nw)
	})

	var deleted []model.Network
	var changed bool
	h := syncHelper[model.Network, string]{
		delete: func(obj *model.Network) error {
			e := wr.writer.Delete(TblNetworks, obj)
			if e == nil || errors.Is(e, memdb.ErrNotFound) {
				changed = true
				deleted = append(deleted, *obj)
			}
			return e
		},
		upsert: func(obj *model.Network) error {
			e := wr.writer.Upsert(TblNetworks, obj)
			changed = changed || e == nil
			return e
		},
		postprocess: func() error {
			return wr.afterDeleteNetworks(ctx, deleted)
		},
	}
	if err = h.doSync(networks, it, opts...); err == nil && changed {
		err = wr.updateSyncStatus(ctx)
	}
	return errors.WithMessage(err, api)
}

// SyncSecurityGroups impl Writer = update / delete security groups
func (wr sGroupsMemDbWriter) SyncSecurityGroups(ctx context.Context, sgs []model.SecurityGroup, scope Scope, opts ...Option) error {
	const api = "mem-db/SyncSecurityGroups"

	it, err := wr.writer.Get(TblSecGroups, indexID)
	if err != nil {
		return errors.WithMessage(err, api)
	}
	var ft filterTree[model.SecurityGroup]
	if !ft.init(scope) {
		return errors.Errorf("bad scope")
	}
	it = memdb.NewFilterIterator(it, func(i interface{}) bool {
		sg := *i.(*model.SecurityGroup)
		return !ft.invoke(sg)
	})

	var deleted []model.SecurityGroup
	var changed bool
	h := syncHelper[model.SecurityGroup, string]{
		upsert: func(obj *model.SecurityGroup) error {
			e := wr.writer.Upsert(TblSecGroups, obj)
			changed = changed || e == nil
			return e
		},
		delete: func(obj *model.SecurityGroup) error {
			e := wr.writer.Delete(TblSecGroups, obj)
			if e == nil || errors.Is(e, memdb.ErrNotFound) {
				changed = true
				deleted = append(deleted, *obj)
			}
			return e
		},
		postprocess: func() error {
			return wr.afterDeleteSGs(ctx, deleted)
		},
	}
	if err = h.doSync(sgs, it, opts...); err == nil && changed {
		err = wr.updateSyncStatus(ctx)
	}
	return errors.WithMessage(err, api)
}

// SyncSGRules impl Writer = update / delete security group rules
func (wr sGroupsMemDbWriter) SyncSGRules(ctx context.Context, rules []model.SGRule, scope Scope, opts ...Option) error {
	const api = "mem-db/SyncSGRules"

	it, err := wr.writer.Get(TblSecRules, indexID)
	if err != nil {
		return errors.WithMessage(err, api)
	}
	var ft filterTree[model.SGRule]
	if !ft.init(scope) {
		return errors.Errorf("bad scope")
	}
	it = memdb.NewFilterIterator(it, func(i interface{}) bool {
		r := *i.(*model.SGRule)
		return !ft.invoke(r)
	})

	var changed bool
	h := syncHelper[model.SGRule, string]{
		delete: func(obj *model.SGRule) error {
			e := wr.writer.Delete(TblSecRules, obj)
			if errors.Is(e, memdb.ErrNotFound) {
				return nil
			}
			changed = changed || e == nil
			return e
		},
		upsert: func(obj *model.SGRule) error {
			e := wr.writer.Upsert(TblSecRules, obj)
			changed = changed || e == nil
			return e
		},
	}
	if err = h.doSync(rules, it, opts...); err == nil && changed {
		err = wr.updateSyncStatus(ctx)
	}
	return errors.WithMessage(err, api)
}

// Commit impl Writer
func (wr sGroupsMemDbWriter) Commit() error {
	return wr.writer.Commit()
}

// Abort impl Writer
func (wr sGroupsMemDbWriter) Abort() {
	wr.writer.Abort()
}

func (wr sGroupsMemDbWriter) afterDeleteNetworks(ctx context.Context, nw []model.Network) error {
	if len(nw) == 0 {
		return nil
	}
	nwNames := make([]model.NetworkName, 0, len(nw))
	nwSet := make(map[model.NetworkName]bool)
	for i := range nw {
		nwSet[nw[i].Name] = true
		nwNames = append(nwNames, nw[i].Name)
	}
	scope := NetworkNames(nwNames...)
	var sgs []model.SecurityGroup
	//get related SG(s)
	err := wr.ListSecurityGroups(ctx, func(sg model.SecurityGroup) error {
		nws := sg.Networks[:0]
		for _, nwName := range sg.Networks {
			if !nwSet[nwName] {
				nws = append(nws, nwName)
			}
		}
		if len(nws) != len(sg.Networks) {
			sg.Networks = nws
			sgs = append(sgs, sg)
		}
		return nil
	}, scope)
	if err != nil {
		return errors.WithMessage(err, "get related SG(s)")
	}
	//update related SG(s)
	for i := range sgs {
		s := &sgs[i]
		if err = wr.writer.Upsert(TblSecGroups, s); err != nil {
			return errors.WithMessagef(err, "update related '%s' SG", s.Name)
		}
	}
	return nil
}

func (wr sGroupsMemDbWriter) afterDeleteSGs(ctx context.Context, sgs []model.SecurityGroup) error {
	if len(sgs) == 0 {
		return nil
	}
	names := make([]string, 0, len(sgs))
	for i := range sgs {
		names = append(names, sgs[i].Name)
	}
	scope := Or(SGFrom(names[0], names[1:]...), SGTo(names[0], names[1:]...))

	//delete related SGRule(s)
	err := wr.SyncSGRules(ctx, nil,
		scope, SyncOmitInsert{}, SyncOmitUpdate{})

	return errors.WithMessage(err, "delete related SGRule(s)")
}

func (wr sGroupsMemDbWriter) updateSyncStatus(_ context.Context) error {
	x := syncStatus{
		ID: 1,
		SyncStatus: model.SyncStatus{
			UpdatedAt: time.Now(),
		},
	}
	err := wr.writer.Upsert(TblSyncStatus, x)
	if isInvalidTableErr(err) {
		err = nil
	}
	return err
}

type syncHelper[T any, TKey comparable] struct {
	cur, new    map[TKey]T
	preprocess  func() error
	upsert      func(*T) error
	delete      func(*T) error
	postprocess func() error
}

func (h *syncHelper[T, TKey]) load(newValues []T, curValIt MemDbIterator) error {
	h.cur = make(map[TKey]T)
	h.new = make(map[TKey]T)
	for _, v := range newValues {
		if e := h.addNew(v); e != nil {
			return e
		}
	}
	for v := curValIt.Next(); v != nil; v = curValIt.Next() {
		if e := h.addCurrent(*v.(*T)); e != nil {
			return e
		}
	}
	return nil
}

func (h syncHelper[T, TKey]) add(v T, toCurrent bool) error {
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

func (h syncHelper[T, TKey]) addNew(v T) error {
	return h.add(v, false)
}

func (h syncHelper[T, TKey]) addCurrent(v T) error {
	return h.add(v, true)
}

func (h syncHelper[T, TKey]) diff(opts ...Option) (upd, ins, del []T) { //nolint:gocyclo
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
			if _, found := h.new[keyCur]; !found {
				del = append(del, vCur)
			}
		}
	}
	return
}

func (h syncHelper[T, TKey]) extractKey(obj T) (TKey, error) {
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

func (h syncHelper[T, TKey]) isEQ(l, r T) bool {
	switch lt := interface{}(l).(type) {
	case net.IPNet:
		rt := interface{}(r).(net.IPNet)
		return lt.IP.Equal(rt.IP) &&
			bytes.Equal(lt.Mask, rt.Mask)
	case model.Network:
		rt := interface{}(r).(model.Network)
		var h syncHelper[net.IPNet, string]
		return h.isEQ(lt.Net, rt.Net)
	case model.SecurityGroup:
		rt := interface{}(r).(model.SecurityGroup)
		if len(lt.Networks) == len(rt.Networks) {
			a := make(map[model.NetworkName]bool, len(lt.Networks))
			for _, nwName := range lt.Networks {
				a[nwName] = true
			}
			for _, nwName := range rt.Networks {
				if ok := a[nwName]; ok {
					delete(a, nwName)
					continue
				}
				return false
			}
			return len(a) == 0
		}
	case model.SGRule:
		rt := interface{}(r).(model.SGRule)
		return lt.IsEq(rt)
	default:
	}
	return false
}

func (h syncHelper[T, TKey]) doSync(newValues []T, curValIt MemDbIterator, opts ...Option) error {
	var err error
	if h.preprocess != nil {
		err = h.preprocess()
		if err != nil {
			return err
		}
	}
	if err = h.load(newValues, curValIt); err != nil {
		return err
	}
	upd, ins, del := h.diff(opts...)
	for i := range del {
		if err = h.delete(&del[i]); err != nil {
			return err
		}
	}
	ups := append(upd, ins...)
	for i := range ups {
		obj := &ups[i]
		if v, ok := any(obj).(model.Validatable); ok {
			err = v.Validate()
			if err != nil {
				return multierr.Combine(ErrValidate, err)
			}
		}
		if err = h.upsert(obj); err != nil {
			return err
		}
	}
	if h.postprocess != nil {
		err = h.postprocess()
	}
	return err
}
