package sgroups

import (
	"context"
	"net/url"
	"time"

	model "github.com/H-BF/sgroups/internal/models/sgroups"

	"github.com/H-BF/sgroups/internal/registry/sgroups/pg"
	atm "github.com/H-BF/sgroups/pkg/atomic"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pkg/errors"
)

// NewRegistryFromPG creates registry from Postgres
func NewRegistryFromPG(ctx context.Context, dbURL url.URL) (r Registry, err error) {
	var conf *pgxpool.Config
	defer func() {
		if err != nil {
			err = errors.WithMessage(err, "NewRegistryFromPG")
		}
	}()
	if conf, err = pgxpool.ParseConfig(dbURL.String()); err != nil {
		return nil, err
	}
	//TODO: Add TLS config
	conf.MaxConns = 20                        //TODO: move into options
	conf.HealthCheckPeriod = 30 * time.Second //TODO: move into options
	conf.AfterConnect = func(ctx context.Context, c *pgx.Conn) error {
		return pg.RegisterSGroupsTypesOntoPGX(ctx, c)
	}
	var pool *pgxpool.Pool
	if pool, err = pgxpool.NewWithConfig(ctx, conf); err != nil {
		return nil, err
	}
	ret := new(pgDbRegistry)
	ret.status.Store(model.SyncStatus{UpdatedAt: time.Now()}, nil)
	ret.pool.Store(pool, nil)
	return ret, nil
}

var _ Registry = (*pgDbRegistry)(nil)

type pgDbRegistry struct {
	pool   atm.Value[*pgxpool.Pool]
	status atm.Value[model.SyncStatus]
}

// Reader impl Registry interface
func (imp *pgDbRegistry) Reader(ctx context.Context) (r Reader, err error) {
	defer func() {
		err = errors.WithMessage(err, "PG/Reader")
	}()
	err = ErrNoRegistry
	status := &imp.status

	type fu = func(context.Context) (*pgxpool.Conn, error)
	var connAccurer atm.Value[fu]
	_ = imp.pool.Fetch(func(p *pgxpool.Pool) {
		connAccurer.Store(func(ctx1 context.Context) (*pgxpool.Conn, error) {
			return p.Acquire(ctx1)
		}, nil)
		ret := new(pgDbReader)
		ret.doIt = func(ctx1 context.Context, f func(*pgx.Conn) error) error {
			cc, ok := connAccurer.Load()
			if !ok {
				return ErrReaderClosed
			}
			c, e := cc(ctx1)
			if e != nil {
				return e
			}
			defer c.Release()
			return f(c.Conn())
		}
		ret.close = func() {
			connAccurer.Clear(nil)
		}
		ret.getStatus = func() *model.SyncStatus {
			if ret, ok := status.Load(); ok {
				return &ret
			}
			return nil
		}
		r = ret
		err = nil
	})
	return r, err
}

// Writer impl Registry interface
func (imp *pgDbRegistry) Writer(ctx context.Context) (w Writer, err error) {
	defer func() {
		err = errors.WithMessage(err, "PG/Writer")
	}()
	err = ErrNoRegistry
	status := &imp.status
	_ = imp.pool.Fetch(func(v *pgxpool.Pool) {
		var txHolder atm.Value[pgx.Tx]
		var tx pgx.Tx
		txOpts := pgx.TxOptions{
			IsoLevel:   pgx.Serializable,
			AccessMode: pgx.ReadWrite,
		}
		if tx, err = v.BeginTx(ctx, txOpts); err != nil {
			return
		}
		txHolder.Store(tx, nil)
		err = nil
		affected := new(uint64)
		w = &pgDbWriter{
			affectedRows: affected,
			tx: func() (pgx.Tx, error) {
				x, ok := txHolder.Load()
				if !ok {
					return nil, ErrWriterClosed
				}
				return x, nil
			},
			abort: func() {
				txHolder.Clear(func(t pgx.Tx) {
					_ = t.Rollback(ctx)
				})
			},
			commit: func() error {
				e := ErrWriterClosed
				txHolder.Clear(func(t pgx.Tx) {
					if *affected == 0 {
						_ = t.Rollback(ctx)
						e = nil
					} else if e = t.Commit(ctx); e != nil {
						_ = t.Rollback(ctx)
					} else {
						e = nil
					}
				})
				return e
			},
			getStatus: func() *model.SyncStatus {
				st, _ := status.Load()
				return &st
			},
			updStatus: func() {
				st := model.SyncStatus{
					UpdatedAt: time.Now(),
				}
				status.Store(st, nil)
			},
		}
	})
	return w, err
}

// Close impl Registry interface
func (imp *pgDbRegistry) Close() error {
	imp.pool.Clear(func(p *pgxpool.Pool) {
		p.Close()
	})
	return nil
}
