package main

import (
	"fmt"
	"os"

	"github.com/H-BF/sgroups/v2/internal/app"
	. "github.com/H-BF/sgroups/v2/internal/app/sgroups-server" //nolint:revive

	_ "github.com/H-BF/corlib/app/identity"
	"github.com/H-BF/corlib/logger"
	pkgNet "github.com/H-BF/corlib/pkg/net"
	config "github.com/H-BF/corlib/pkg/plain-config"
	"github.com/H-BF/corlib/server"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
)

func main() {
	SetupContext()
	ctx := app.Context()
	logger.SetLevel(zap.InfoLevel)
	logger.Info(ctx, "-= HELLO =-")
	err := config.InitGlobalConfig(
		config.WithAcceptEnvironment{EnvPrefix: "SG"},
		config.WithSourceFile{FileName: ConfigFile},
		config.WithDefValue(LoggerLevel, "DEBUG"),
		config.WithDefValue(MetricsEnable, true),
		config.WithDefValue(HealthcheckEnable, true),
		config.WithDefValue(ServerGracefulShutdown, "10s"),
		config.WithDefValue(ServerEndpoint, "tcp://127.0.0.1:9000"),
		config.WithDefValue(StorageType, "INTERNAL"),
		config.WithDefValue(AuthnType, config.AuthnTypeNONE),
	)
	if err != nil {
		logger.Fatal(ctx, err)
	}
	if err = SetupLogger(); err != nil {
		logger.Fatal(ctx, errors.WithMessage(err, "when setup logger"))
	}

	if MetricsEnable.MustValue(ctx) {
		opt := app.AddMetrics{
			Metrics: []prometheus.Collector{app.NewHealthcheckMetric(nil)},
		}
		err = app.SetupMetrics(opt)
		if err != nil {
			logger.Fatal(ctx, errors.WithMessage(err, "when setup metrics"))
		}
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
	if err = SetupRegistry(); err != nil {
		logger.Fatal(ctx, errors.WithMessage(err, "on opening db storade"))
	}
	var srv *server.APIServer
	if srv, err = SetupSgServer(ctx); err != nil {
		logger.Fatalf(ctx, "setup server: %v", err)
	}
	gracefulDuration, _ := ServerGracefulShutdown.Value(ctx)
	if err = srv.Run(ctx, ep, server.RunWithGracefulStop(gracefulDuration)); err != nil {
		logger.Fatalf(ctx, "run server: %v", err)
	}
	logger.SetLevel(zap.InfoLevel)
	logger.Info(ctx, "-= BYE =-")
}

func init() {
	if false {
		os.Setenv("SG_SERVER_API-PATH-PREFIX", "/abc")
	}
	if false {
		//const pre = `./../../bin`
		const pre = `.`
		os.Setenv("SG_AUTHN_TYPE", string(config.AuthnTypeTLS))
		os.Setenv("SG_AUTHN_TLS_KEY-FILE", fmt.Sprintf("%s/tls/server-key.pem", pre))
		os.Setenv("SG_AUTHN_TLS_CERT-FILE", fmt.Sprintf("%s/tls/server-cert.pem", pre))
		//os.Setenv("SG_AUTHN_TLS_CLIENT_CA-FILES", fmt.Sprintf(`["%s/tls/ca-cert.pem"]`, pre))
		os.Setenv("SG_AUTHN_TLS_CLIENT_VERIFY", string(config.TLSclientSkipVerify))
	}
}
