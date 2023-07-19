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
	_ = imp.pool.Fetch(func(v *pgxpool.Pool) {
		var c *pgxpool.Conn
		if c, err = v.Acquire(ctx); err != nil {
			return
		}
		var h atm.Value[*pgxpool.Conn]
		h.Store(c, nil)
		err = nil
		r = &pgDbReader{
			close: func() {
				h.Clear(func(c *pgxpool.Conn) {
					c.Release()
				})
			},
			conn: func() (*pgx.Conn, error) {
				var ret *pgx.Conn
				e := ErrReaderClosed
				_ = h.Fetch(func(c *pgxpool.Conn) {
					ret, e = c.Conn(), nil
				})
				return ret, e
			},
			getStatus: func() *model.SyncStatus {
				if ret, ok := status.Load(); ok {
					return &ret
				}
				return nil
			},
		}
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
		var h atm.Value[pgx.Tx]
		var tx pgx.Tx
		if tx, err = v.Begin(ctx); err != nil {
			return
		}
		h.Store(tx, nil)
		err = nil
		w = &pgDbWriter{
			pgDbReader: &pgDbReader{
				conn: func() (*pgx.Conn, error) {
					var c *pgx.Conn
					e := ErrWriterClosed
					_ = h.Fetch(func(t pgx.Tx) {
						c, e = t.Conn(), nil
					})
					return c, e
				},
				getStatus: func() *model.SyncStatus {
					if ret, ok := status.Load(); ok {
						return &ret
					}
					return nil
				},
			},
			abort: func() {
				h.Clear(func(t pgx.Tx) {
					_ = t.Rollback(ctx)
				})
			},
			commit: func() error {
				e := ErrWriterClosed
				h.Clear(func(t pgx.Tx) {
					e = t.Commit(ctx)
				})
				return e
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
