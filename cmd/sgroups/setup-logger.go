package main

import (
	"github.com/H-BF/corlib/logger"
	"github.com/H-BF/sgroups/internal/app"
	"github.com/pkg/errors"
)

func setupLogger() error {
	ctx := app.Context()
	_, err := LoggerLevel.Value(ctx, LoggerLevel.OptSink(func(v string) error {
		var l logger.LogLevel
		if e := l.UnmarshalText([]byte(v)); e != nil {
			return errors.Wrapf(e, "recognize '%s' logger level from config", v)
		}
		logger.SetLevel(l)
		return nil
	}))
	return err
}
