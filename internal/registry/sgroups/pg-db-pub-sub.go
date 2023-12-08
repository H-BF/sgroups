package sgroups

import (
	"context"
	"errors"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/puddle/v2"
)

const (
	// NotifyCommit -
	NotifyCommit = "commit"
)

func (dbimp *pgDbRegistry) listenMessages(ctx context.Context) {
	const timeoutBeforeRetry = 10 * time.Second

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
				pid := os.Getpid()
				if nt.Channel == NotifyCommit && nt.PID != uint32(pid) {
					dbimp.subject.Notify(DBUpdated{})
				}
			}
		})
		if errors.Is(err, puddle.ErrClosedPool) {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(timeoutBeforeRetry):
		}
	}
}
