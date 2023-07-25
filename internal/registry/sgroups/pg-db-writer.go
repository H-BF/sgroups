package sgroups

import (
	"context"

	model "github.com/H-BF/sgroups/internal/models/sgroups"
	"github.com/H-BF/sgroups/internal/registry/sgroups/pg"

	"github.com/jackc/pgx/v5"
	"github.com/pkg/errors"
)

var _ Writer = (*pgDbWriter)(nil)

type pgDbWriter struct {
	tx        func() (pgx.Tx, error)
	commit    func() error
	abort     func()
	getStatus func() *model.SyncStatus
	updStatus func()
}

// SyncNetworks impl Writer interface
func (wr *pgDbWriter) SyncNetworks(ctx context.Context, networks []model.Network, scope Scope, opts ...Option) error {
	const api = "PG/SyncNetworks"

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
		for nw := range v.Names {
			if err = snc.AddToFilter(ctx, nw); err != nil {
				return err
			}
		}
	case noScope:
	default:
		return ErrUnexpectedScope
	}
	_, err = snc.Sync(ctx)

	return err
}

// SyncSecurityGroups impl Writer interface
func (wr *pgDbWriter) SyncSecurityGroups(ctx context.Context, sgs []model.SecurityGroup, scope Scope, opts ...Option) error {
	const api = "PG/SyncSecurityGroups"

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
	if err = snc.AddData(ctx, sgs...); err != nil {
		return err
	}
	switch v := scope.(type) {
	case scopedSG:
		for n := range v {
			if err = snc.AddToFilter(ctx, n); err != nil {
				return err
			}
		}
	case noScope:
	default:
		return ErrUnexpectedScope
	}
	_, err = snc.Sync(ctx)
	return err
}

// SyncSGRules impl Writer interface
func (wr *pgDbWriter) SyncSGRules(ctx context.Context, rules []model.SGRule, scope Scope, opts ...Option) error {
	const api = "PG/SyncSGRules"

	var err error
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
		for _, id := range v {
			if err = snc.AddToFilter(ctx, id); err != nil {
				return err
			}
		}
	case noScope:
	default:
		return ErrUnexpectedScope
	}
	_, err = snc.Sync(ctx)
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
