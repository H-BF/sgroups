package sgroups

import (
	"context"
	"time"

	model "github.com/H-BF/sgroups/internal/models/sgroups"
	"github.com/H-BF/sgroups/internal/patterns"

	"github.com/hashicorp/go-memdb"
	"github.com/pkg/errors"
	"go.uber.org/multierr"
)

type sGroupsMemDbWriter struct {
	sGroupsMemDbReader
	writer  MemDbWriter
	subject patterns.Subject
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
		keyExtract: func(n *model.Network) string {
			return n.Name
		},
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
		keyExtract: func(sg *model.SecurityGroup) string {
			return sg.Name
		},
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
func (wr sGroupsMemDbWriter) SyncSGRules(ctx context.Context, rules []model.SGRule, scope Scope, opts ...Option) error { //nolint:dupl
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
	h := syncHelper[model.SGRule, model.SGRuleIdentity]{
		keyExtract: func(rt *model.SGRule) model.SGRuleIdentity {
			return rt.ID
		},
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

// SyncFqdnRules impl Writer = update / delete FQQN rules
func (wr sGroupsMemDbWriter) SyncFqdnRules(ctx context.Context, rules []model.FQDNRule, scope Scope, opts ...Option) error { //nolint:dupl
	const api = "mem-db/SyncFqdnRules"

	it, err := wr.writer.Get(TblFqdnRules, indexID)
	if err != nil {
		return errors.WithMessage(err, api)
	}
	var ft filterTree[model.FQDNRule]
	if !ft.init(scope) {
		return errors.Errorf("bad scope")
	}
	it = memdb.NewFilterIterator(it, func(i interface{}) bool {
		r := *i.(*model.FQDNRule)
		return !ft.invoke(r)
	})

	var changed bool
	h := syncHelper[model.FQDNRule, model.FQDNRuleIdentity]{
		keyExtract: func(rt *model.FQDNRule) model.FQDNRuleIdentity {
			return rt.ID
		},
		delete: func(obj *model.FQDNRule) error {
			e := wr.writer.Delete(TblFqdnRules, obj)
			if errors.Is(e, memdb.ErrNotFound) {
				return nil
			}
			changed = changed || e == nil
			return e
		},
		upsert: func(obj *model.FQDNRule) error {
			e := wr.writer.Upsert(TblFqdnRules, obj)
			changed = changed || e == nil
			return e
		},
	}
	if err = h.doSync(rules, it, opts...); err == nil && changed {
		err = wr.updateSyncStatus(ctx)
	}
	return errors.WithMessage(err, api)
}

// SyncSgIcmpRules impl Writer = update / delete SG:ICMP rules
func (wr sGroupsMemDbWriter) SyncSgIcmpRules(ctx context.Context, rules []model.SgIcmpRule, scope Scope, opts ...Option) error { //nolint:dupl
	const api = "mem-db/SyncSgIcmpRules"

	it, err := wr.writer.Get(TblSgIcmpRules, indexID)
	if err != nil {
		return errors.WithMessage(err, api)
	}
	var ft filterTree[model.SgIcmpRule]
	if !ft.init(scope) {
		return errors.Errorf("bad scope")
	}
	it = memdb.NewFilterIterator(it, func(i interface{}) bool {
		r := *i.(*model.SgIcmpRule)
		return !ft.invoke(r)
	})

	var changed bool
	h := syncHelper[model.SgIcmpRule, model.SgIcmpRuleID]{
		keyExtract: func(r *model.SgIcmpRule) model.SgIcmpRuleID {
			return r.ID()
		},
		delete: func(obj *model.SgIcmpRule) error {
			e := wr.writer.Delete(TblSgIcmpRules, obj)
			if errors.Is(e, memdb.ErrNotFound) {
				return nil
			}
			changed = changed || e == nil
			return e
		},
		upsert: func(obj *model.SgIcmpRule) error {
			e := wr.writer.Upsert(TblSgIcmpRules, obj)
			changed = changed || e == nil
			return e
		},
	}
	if err = h.doSync(rules, it, opts...); err == nil && changed {
		err = wr.updateSyncStatus(ctx)
	}
	return errors.WithMessage(err, api)
}

// SyncSgSgIcmpRules impl Writer = update / delete SG-SG:ICMP rules
func (wr sGroupsMemDbWriter) SyncSgSgIcmpRules(ctx context.Context, rules []model.SgSgIcmpRule, scope Scope, opts ...Option) error { //nolint:dupl
	const api = "mem-db/SyncSgSgIcmpRules"

	it, err := wr.writer.Get(TblSgSgIcmpRules, indexID)
	if err != nil {
		return errors.WithMessage(err, api)
	}
	var ft filterTree[model.SgIcmpRule]
	if !ft.init(scope) {
		return errors.Errorf("bad scope")
	}
	it = memdb.NewFilterIterator(it, func(i interface{}) bool {
		r := *i.(*model.SgIcmpRule)
		return !ft.invoke(r)
	})

	var changed bool
	h := syncHelper[model.SgSgIcmpRule, model.SgSgIcmpRuleID]{
		keyExtract: func(r *model.SgSgIcmpRule) model.SgSgIcmpRuleID {
			return r.ID()
		},
		delete: func(obj *model.SgSgIcmpRule) error {
			e := wr.writer.Delete(TblSgSgIcmpRules, obj)
			if errors.Is(e, memdb.ErrNotFound) {
				return nil
			}
			changed = changed || e == nil
			return e
		},
		upsert: func(obj *model.SgSgIcmpRule) error {
			e := wr.writer.Upsert(TblSgSgIcmpRules, obj)
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
	err := wr.writer.Commit()
	if err == nil {
		wr.subject.Notify(DBUpdated{})
	}
	return err
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

	// delete related SGRule(s)
	err1 := wr.SyncSGRules(ctx, nil,
		Or(SGFrom(names[0], names[1:]...), SGTo(names[0], names[1:]...)),
		SyncOmitInsert{}, SyncOmitUpdate{})

	// delete related FQDNRule(s)
	err2 := wr.SyncFqdnRules(ctx, nil,
		SGFrom(names[0], names[1:]...),
		SyncOmitInsert{}, SyncOmitUpdate{})

	// delete related SgIcmpRule(s)
	err3 := wr.SyncSgIcmpRules(ctx, nil,
		SG(names...), SyncOmitInsert{}, SyncOmitUpdate{})

	// delete related SgSgIcmpRule(s)
	err4 := wr.SyncSgSgIcmpRules(ctx, nil,
		Or(SGFrom(names[0], names[1:]...), SGTo(names[0], names[1:]...)),
		SyncOmitInsert{}, SyncOmitUpdate{})

	const delRel = "delete related"
	return multierr.Combine(
		errors.WithMessagef(err1, "%s SGRule(s)", delRel),
		errors.WithMessagef(err2, "%s FQDNRule(s)", delRel),
		errors.WithMessagef(err3, "%s SgIcmpRule(s)", delRel),
		errors.WithMessagef(err4, "%s SgSgIcmpRule(s)", delRel),
	)
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

type syncHelper[T interface{ IsEq(T) bool }, TKey comparable] struct {
	cur, new    map[TKey]T
	keyExtract  func(*T) TKey
	preprocess  func() error
	upsert      func(*T) error
	delete      func(*T) error
	postprocess func() error
}

func (h *syncHelper[T, TKey]) load(newValues []T, curValIt MemDbIterator) error {
	h.cur = make(map[TKey]T)
	h.new = make(map[TKey]T)
	for _, v := range newValues {
		h.add2new(v)
	}
	for v := curValIt.Next(); v != nil; v = curValIt.Next() {
		h.add2current(*v.(*T))
	}
	return nil
}

func (h syncHelper[T, TKey]) add(v T, toCurrent bool) {
	if k := h.keyExtract(&v); toCurrent {
		h.cur[k] = v
	} else {
		h.new[k] = v
	}
}

func (h syncHelper[T, TKey]) add2new(v T) {
	h.add(v, false)
}

func (h syncHelper[T, TKey]) add2current(v T) {
	h.add(v, true)
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
			} else if ok && u && !vNew.IsEq(vCur) {
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
