package sgroups

import (
	"context"
	"strings"
	"sync/atomic"

	model "github.com/H-BF/sgroups/internal/models/sgroups"
	"github.com/H-BF/sgroups/internal/registry/sgroups/pg"

	linq "github.com/ahmetb/go-linq/v3"
	"github.com/jackc/pgx/v5"
	"github.com/pkg/errors"
)

var _ Writer = (*pgDbWriter)(nil)

type pgDbWriter struct {
	tx     func() (pgx.Tx, error)
	commit func() error
	abort  func()

	affectedRows *int64
}

// SyncNetworks impl Writer interface
func (wr *pgDbWriter) SyncNetworks(ctx context.Context, networks []model.Network, scope Scope, opts ...Option) error {
	const api = "PG/SyncNetworks"

	var affected int64
	var err error
	defer func() {
		err = errors.WithMessage(err, api)
	}()

	var tx pgx.Tx
	if tx, err = wr.tx(); err != nil {
		return err
	}
	snc := pg.SyncerOfNetworks{C: tx.Conn()}
	snc.Upd, snc.Ins, snc.Del = wr.opts2flags(opts)
	if err = snc.AddData(ctx, networks...); err != nil {
		return err
	}
	switch v := scope.(type) {
	case scopedNetworks:
		names := make([]string, 0, len(v.Names))
		for nw := range v.Names {
			names = append(names, nw)
		}
		if err = snc.AddToFilter(ctx, names...); err != nil {
			return err
		}
	case noScope:
	default:
		return ErrUnexpectedScope
	}
	affected, err = snc.Sync(ctx)
	if err == nil && affected > 0 {
		atomic.AddInt64(wr.affectedRows, affected)
	}
	return err
}

// SyncSecurityGroups impl Writer interface
func (wr *pgDbWriter) SyncSecurityGroups(ctx context.Context, sgs []model.SecurityGroup, scope Scope, opts ...Option) error {
	const api = "PG/SyncSecurityGroups"

	var affected int64
	var err error
	defer func() {
		err = errors.WithMessage(err, api)
	}()

	var tx pgx.Tx
	if tx, err = wr.tx(); err != nil {
		return err
	}
	snc := pg.SyncerOfSecGroups{C: tx.Conn()}
	snc.Upd, snc.Ins, snc.Del = wr.opts2flags(opts)
	if snc.Upd || snc.Ins {
		err = validateSecGroupsDataIn(sgs)
		if err != nil {
			return err
		}
	}
	if err = snc.AddData(ctx, sgs...); err != nil {
		return err
	}
	switch v := scope.(type) {
	case scopedSG:
		names := make([]string, 0, len(v))
		for n := range v {
			names = append(names, n)
		}
		if err = snc.AddToFilter(ctx, names...); err != nil {
			return err
		}
	case noScope:
	default:
		return ErrUnexpectedScope
	}
	affected, err = snc.Sync(ctx)
	if err == nil && affected > 0 {
		atomic.AddInt64(wr.affectedRows, affected)
	}
	return err
}

// SyncSGRules impl Writer interface
func (wr *pgDbWriter) SyncSGRules(ctx context.Context, rules []model.SGRule, scope Scope, opts ...Option) error { //nolint:dupl
	const api = "PG/SyncSGRules"

	var err error
	var affected int64
	defer func() {
		err = errors.WithMessage(err, api)
	}()
	var tx pgx.Tx
	if tx, err = wr.tx(); err != nil {
		return err
	}
	snc := pg.SyncerOfSgRules{C: tx.Conn()}
	snc.Upd, snc.Ins, snc.Del = wr.opts2flags(opts)
	if err = snc.AddData(ctx, rules...); err != nil {
		return err
	}
	switch v := scope.(type) {
	case scopedSGRuleIdentity:
		ids := make([]model.SGRuleIdentity, 0, len(v))
		for _, id := range v {
			ids = append(ids, id)
		}
		if err = snc.AddToFilter(ctx, ids...); err != nil {
			return err
		}
	case noScope:
	default:
		return ErrUnexpectedScope
	}
	affected, err = snc.Sync(ctx)
	if err == nil && affected > 0 {
		atomic.AddInt64(wr.affectedRows, affected)
	}
	return err
}

// SyncFqdnRules impl Writer interface
func (wr *pgDbWriter) SyncFqdnRules(ctx context.Context, rules []model.FQDNRule, scope Scope, opts ...Option) error { //nolint:dupl
	const api = "PG/SyncSG2FQDNRules"

	var err error
	var affected int64
	defer func() {
		err = errors.WithMessage(err, api)
	}()
	var tx pgx.Tx
	if tx, err = wr.tx(); err != nil {
		return err
	}
	snc := pg.SyncerOfSg2FqdnRules{C: tx.Conn()}
	snc.Upd, snc.Ins, snc.Del = wr.opts2flags(opts)
	if err = snc.AddData(ctx, rules...); err != nil {
		return err
	}
	switch v := scope.(type) {
	case scopedFqdnRuleIdentity:
		ids := make([]model.FQDNRuleIdentity, 0, len(v))
		for _, id := range v {
			ids = append(ids, id)
		}
		if err = snc.AddToFilter(ctx, ids...); err != nil {
			return err
		}
	case noScope:
	default:
		return ErrUnexpectedScope
	}
	affected, err = snc.Sync(ctx)
	if err == nil && affected > 0 {
		atomic.AddInt64(wr.affectedRows, affected)
	}
	return err
}

// SyncSgIcmpRules impl Writer interface
func (wr *pgDbWriter) SyncSgIcmpRules(ctx context.Context, rules []model.SgIcmpRule, scope Scope, opts ...Option) error { //nolint:dupl
	const api = "PG/SyncSgIcmpRules"

	var err error
	var affected int64
	defer func() {
		err = errors.WithMessage(err, api)
	}()
	var tx pgx.Tx
	if tx, err = wr.tx(); err != nil {
		return err
	}
	snc := pg.SyncerOfSgIcmpRules{C: tx.Conn()}
	snc.Upd, snc.Ins, snc.Del = wr.opts2flags(opts)
	if err = snc.AddData(ctx, rules...); err != nil {
		return err
	}
	switch v := scope.(type) {
	case scopedSgIcmpIdentity:
		ids := make([]model.SgIcmpRuleID, 0, len(v))
		for _, id := range v {
			ids = append(ids, id)
		}
		if err = snc.AddToFilter(ctx, ids...); err != nil {
			return err
		}
	case noScope:
	default:
		return ErrUnexpectedScope
	}
	affected, err = snc.Sync(ctx)
	if err == nil && affected > 0 {
		atomic.AddInt64(wr.affectedRows, affected)
	}
	return err
}

// SyncSgIcmpRules impl Writer interface
func (wr *pgDbWriter) SyncSgSgIcmpRules(ctx context.Context, rules []model.SgSgIcmpRule, scope Scope, opts ...Option) error { //nolint:dupl
	const api = "PG/SyncSgSgIcmpRules"

	var err error
	var affected int64
	defer func() {
		err = errors.WithMessage(err, api)
	}()
	var tx pgx.Tx
	if tx, err = wr.tx(); err != nil {
		return err
	}
	snc := pg.SyncerOfSgSgIcmpRules{C: tx.Conn()}
	snc.Upd, snc.Ins, snc.Del = wr.opts2flags(opts)
	if err = snc.AddData(ctx, rules...); err != nil {
		return err
	}
	switch v := scope.(type) {
	case scopedSgSgIcmpIdentity:
		ids := make([]model.SgSgIcmpRuleID, 0, len(v))
		for _, id := range v {
			ids = append(ids, id)
		}
		if err = snc.AddToFilter(ctx, ids...); err != nil {
			return err
		}
	case noScope:
	default:
		return ErrUnexpectedScope
	}
	affected, err = snc.Sync(ctx)
	if err == nil && affected > 0 {
		atomic.AddInt64(wr.affectedRows, affected)
	}
	return err
}

// SyncCidrSgRules impl Writer interface
func (wr *pgDbWriter) SyncCidrSgRules(ctx context.Context, rules []model.CidrSgRule, scope Scope, opts ...Option) error { //nolint:dupl
	const api = "PG/SyncCidrSgRules"

	var err error
	var affected int64
	defer func() {
		err = errors.WithMessage(err, api)
	}()
	var tx pgx.Tx
	if tx, err = wr.tx(); err != nil {
		return err
	}
	snc := pg.SyncerOfCidrSgRules{C: tx.Conn()}
	snc.Upd, snc.Ins, snc.Del = wr.opts2flags(opts)
	if err = snc.AddData(ctx, rules...); err != nil {
		return err
	}
	switch v := scope.(type) {
	case scopedCidrSgRuleIdentity:
		ids := make([]model.CidrSgRuleIdenity, 0, len(v))
		for _, id := range v {
			ids = append(ids, id)
		}
		if err = snc.AddToFilter(ctx, ids...); err != nil {
			return err
		}
	case noScope:
	default:
		return ErrUnexpectedScope
	}
	affected, err = snc.Sync(ctx)
	if err == nil && affected > 0 {
		atomic.AddInt64(wr.affectedRows, affected)
	}
	return err
}

// SyncSgSgRules impl Writer interface
func (wr *pgDbWriter) SyncSgSgRules(ctx context.Context, rules []model.SgSgRule, scope Scope, opts ...Option) error { //nolint:dupl
	const api = "PG/SyncSgSgRules"

	var err error
	var affected int64
	defer func() {
		err = errors.WithMessage(err, api)
	}()
	var tx pgx.Tx
	if tx, err = wr.tx(); err != nil {
		return err
	}
	snc := pg.SyncerOfSgSgRules{C: tx.Conn()}
	snc.Upd, snc.Ins, snc.Del = wr.opts2flags(opts)
	if err = snc.AddData(ctx, rules...); err != nil {
		return err
	}
	switch v := scope.(type) {
	case scopedSgSgRuleIdentity:
		ids := make([]model.SgSgRuleIdentity, 0, len(v))
		for _, id := range v {
			ids = append(ids, id)
		}
		if err = snc.AddToFilter(ctx, ids...); err != nil {
			return err
		}
	case noScope:
	default:
		return ErrUnexpectedScope
	}
	affected, err = snc.Sync(ctx)
	if err == nil && affected > 0 {
		atomic.AddInt64(wr.affectedRows, affected)
	}
	return err
}

// SyncIESgSgIcmpRules impl Writer interface
func (wr *pgDbWriter) SyncIESgSgIcmpRules(ctx context.Context, rules []model.IESgSgIcmpRule, scope Scope, opts ...Option) error { //nolint:dupl
	const api = "PG/SyncIESgSgIcmpRules"

	var err error
	var affected int64
	defer func() {
		err = errors.WithMessage(err, api)
	}()
	var tx pgx.Tx
	if tx, err = wr.tx(); err != nil {
		return err
	}
	snc := pg.SyncerOfIESgSgIcmpRules{C: tx.Conn()}
	snc.Upd, snc.Ins, snc.Del = wr.opts2flags(opts)
	if err = snc.AddData(ctx, rules...); err != nil {
		return err
	}
	switch v := scope.(type) {
	case scopedIESgSgIcmpRuleIdentity:
		ids := make([]model.IESgSgIcmpRuleID, 0, len(v))
		for _, id := range v {
			ids = append(ids, id)
		}
		if err = snc.AddToFilter(ctx, ids...); err != nil {
			return err
		}
	case noScope:
	default:
		return ErrUnexpectedScope
	}
	affected, err = snc.Sync(ctx)
	if err == nil && affected > 0 {
		atomic.AddInt64(wr.affectedRows, affected)
	}
	return err
}

// Commit impl Writer interface
func (wr *pgDbWriter) Commit() error {
	return wr.commit()
}

// Abort impl Writer interface
func (wr *pgDbWriter) Abort() {
	wr.abort()
}

func (wr *pgDbWriter) opts2flags(opts []Option) (upd, ins, del bool) {
	upd, ins, del = true, true, true
	for i := range opts {
		switch opts[i].(type) {
		case SyncOmitDelete:
			del = false
		case SyncOmitInsert:
			ins = false
		case SyncOmitUpdate:
			upd = false
		}
	}
	return upd, ins, del
}

func validateSecGroupsDataIn(sgs []model.SecurityGroup) error {
	type nw2sg = struct {
		Network model.NetworkName
		SgName  string
	}
	fi := linq.From(sgs).
		SelectManyT(func(sg model.SecurityGroup) linq.Query {
			return linq.Query{
				Iterate: func() linq.Iterator {
					i := -1
					return func() (any, bool) {
						if i++; i < len(sg.Networks) {
							return nw2sg{sg.Networks[i], sg.Name}, true
						}
						return nil, false
					}
				},
			}
		}).GroupByT(
		func(o nw2sg) model.NetworkName {
			return o.Network
		},
		func(o nw2sg) string {
			return o.SgName
		},
	).Select(func(i any) any {
		g := i.(linq.Group)
		if len(g.Group) > 1 {
			x := g.Group[:0]
			linq.From(g.Group).Distinct().ToSlice(&x)
			g.Group = x
		}
		return g
	}).FirstWith(func(g any) bool {
		return len(g.(linq.Group).Group) > 1
	})
	switch v := fi.(type) {
	case nil:
	case linq.Group:
		var sg []string
		linq.From(v.Group).ToSlice(&sg)
		return errors.Errorf("the network '%s' belongs to multiple SG [%s]",
			v.Key.(string), strings.Join(sg, ","))
	default:
		panic("UB")
	}
	return nil
}
