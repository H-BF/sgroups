package server

import (
	"context"

	"github.com/H-BF/corlib/logger"
	"github.com/H-BF/corlib/pkg/signals"
	"github.com/H-BF/sgroups/internal/app"
	"go.uber.org/zap"
)

// SetupContext -
func SetupContext() {
	ctx, cancel := context.WithCancel(context.Background())
	signals.WhenSignalExit(func() error {
		logger.SetLevel(zap.InfoLevel)
		logger.Info(ctx, "caught application stop signal")
		cancel()
		return nil
	})
	app.SetContext(ctx)
}
