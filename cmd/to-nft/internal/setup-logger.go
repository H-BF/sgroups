package internal

import (
	"github.com/H-BF/corlib/logger"
	"github.com/H-BF/sgroups/internal/app"
	"github.com/pkg/errors"
)

// SetupLogger setup app logger
func SetupLogger() error {
	ctx := app.Context()
	_, err := AppLoggerLevel.Value(ctx, AppLoggerLevel.OptSink(func(v string) error {
		var l logger.LogLevel
		if e := l.UnmarshalText([]byte(v)); e != nil {
			return errors.Wrapf(e, "recognize '%s' logger level from config", v)
		}
		logger.SetLevel(l)
		return nil
	}))
	return err
}
