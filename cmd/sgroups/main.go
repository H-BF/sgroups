package main

import (
	_ "github.com/H-BF/corlib/app/identity"
	"github.com/H-BF/corlib/logger"
	pkgNet "github.com/H-BF/corlib/pkg/net"
	"github.com/H-BF/corlib/server"
	"github.com/H-BF/sgroups/internal/app"
	"github.com/H-BF/sgroups/internal/config"
	"github.com/pkg/errors"
	"go.uber.org/zap"

	_ "github.com/jackc/pgx/v4"
)

func main() {
	setupContext()
	ctx := app.Context()
	logger.SetLevel(zap.InfoLevel)
	logger.Info(ctx, "-= HELLO =-")
	err := config.InitGlobalConfig(
		config.WithAcceptEnvironment{EnvPrefix: "SG"},
		config.WithSourceFile{FileName: ConfigFile},
		config.WithDefValue{Key: LoggerLevel, Val: "DEBUG"},
		config.WithDefValue{Key: MetricsEnable, Val: true},
		config.WithDefValue{Key: ServerGracefulShutdown, Val: "10s"},
		config.WithDefValue{Key: ServerEndpoint, Val: "tcp://127.0.0.1:9000"},
	)
	if err != nil {
		logger.Fatal(ctx, err)
	}
	if err = setupLogger(); err != nil {
		logger.Fatal(ctx, errors.WithMessage(err, "when setup logger"))
	}
	if err = setupMetrics(); err != nil {
		logger.Fatal(ctx, errors.WithMessage(err, "when setup metrics"))
	}

	var ep *pkgNet.Endpoint
	_, err = ServerEndpoint.Value(ctx, ServerEndpoint.OptSink(func(v string) error {
		var e error
		if ep, e = pkgNet.ParseEndpoint(v); e != nil {
			logger.Fatalf(ctx, "parse server endpoint (%s): %v", v, err)
		}
		return nil
	}))
	if err != nil && errors.Is(err, config.ErrNotFound) {
		logger.Fatal(ctx, errors.WithMessage(err, "server endpoint is absent"))
	}
	var srv *server.APIServer
	if srv, err = setupSgServer(ctx); err != nil {
		logger.Fatalf(ctx, "setup server: %v", err)
	}
	gracefulDuration, _ := ServerGracefulShutdown.Value(ctx)
	if err = srv.Run(ctx, ep, server.RunWithGracefulStop(gracefulDuration)); err != nil {
		logger.Fatalf(ctx, "run server: %v", err)
	}
	logger.SetLevel(zap.InfoLevel)
	logger.Info(ctx, "-= BYE =-")
}
