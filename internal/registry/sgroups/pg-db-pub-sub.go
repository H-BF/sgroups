package sgroups

import (
	"context"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/puddle/v2"
)

const (
	// NotifyCommit -
	NotifyCommit = "commit"
)

func (dbimp *pgDbRegistry) listenMessages(ctx context.Context) {
	pool, ok := dbimp.pool.Load()
	for ; ok; pool, ok = dbimp.pool.Load() {
		err := pool.AcquireFunc(ctx, func(c *pgxpool.Conn) error {
			conn := c.Conn()
			for {
				nt, e := conn.WaitForNotification(ctx)
				if e != nil {
					return e
				}
				if nt.Channel == NotifyCommit {
					dbimp.subject.Notify(DBUpdated{})
				}
			}
		})
		if err != nil {
			_ = puddle.ErrClosedPool
			_ = puddle.ErrNotAvailable
			_ = pgconn.SafeToRetry
			_ = pgconn.Timeout
			_ = err
		}
	}
}
