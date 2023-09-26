package sgroups

import (
	"context"
	"errors"
	"time"

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
			if _, err := conn.Exec(ctx, "listen "+NotifyCommit); err != nil {
				return err
			}

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
			if errors.Is(err, puddle.ErrClosedPool) {
				// since there is no place where pool restoring when it closed so just return from here
				return
			} else if pgconn.SafeToRetry(err) {
				<-time.After(time.Minute)
				continue
			} else if pgconn.Timeout(err) {
				continue
			} else {
				// any other error kind
				return
			}
		}
	}
}
