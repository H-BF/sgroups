package sgroups

import (
	"context"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"time"
)

type (
	Notification = pgconn.Notification
	channelName  = string
	ntHandler    = func(nt *Notification) error

	pgListener struct {
		subs    map[channelName]ntHandler
		connect func(ctx context.Context) (*pgx.Conn, error)
		logger  func(ctx context.Context, err error)
	}
)

func newPgListener(subscriptions map[channelName]ntHandler) pgListener {
	return pgListener{
		subs: subscriptions,
	}
}

func (listener *pgListener) Listen(ctx context.Context) error {
	if err := listener.assertReadiness(); err != nil {
		listener.logError(ctx, err)
		return err
	}

	for {
		err := listener.listen(ctx)
		if err != nil {
			listener.logError(ctx, err)
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Minute):
			// Do not spam while database is restarting
		}
	}
}

func (listener *pgListener) listen(ctx context.Context) error {
	conn, err := listener.connect(ctx)
	if err != nil {
		return fmt.Errorf("connect failed: %w", err)
	}
	defer func() {
		err := conn.Close(ctx)
		if err != nil {
			return
		}
	}()

	for channel := range listener.subs {
		_, err := conn.Exec(ctx, "listen "+pgx.Identifier{channel}.Sanitize())
		if err != nil {
			return fmt.Errorf("listen %q failed: %w", channel, err)
		}
	}

	for {
		nt, err := conn.WaitForNotification(ctx)
		if err != nil {
			return fmt.Errorf("wait for notification failed: %w", err)
		}
		if handler, ok := listener.subs[nt.Channel]; ok {
			err := handler(nt)
			if err != nil {
				listener.logError(ctx, fmt.Errorf("handle %s notification failed: %w", nt.Channel, err))
			}
		} else {
			listener.logError(ctx, fmt.Errorf("handler not found: %s", nt.Channel))
		}
	}
}

func (listener *pgListener) assertReadiness() error {
	if listener.connect == nil {
		return errors.New("listen: Connect is nil")
	}

	if len(listener.subs) == 0 {
		return errors.New("listen: No subs")
	}
	return nil
}

func (listener *pgListener) logError(ctx context.Context, err error) {
	if listener.logger != nil {
		listener.logger(ctx, err)
	}
}
