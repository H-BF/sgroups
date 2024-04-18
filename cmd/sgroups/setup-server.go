package main

import (
	"context"
	"errors"

	"github.com/H-BF/sgroups/internal/api/sgroups"
	"github.com/H-BF/sgroups/internal/app"
	"github.com/H-BF/sgroups/internal/config"
	_ "github.com/H-BF/sgroups/internal/grpc"

	"github.com/H-BF/corlib/server"
	"github.com/H-BF/corlib/server/interceptors"
	serverPrometheusMetrics "github.com/H-BF/corlib/server/metrics/prometheus"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"google.golang.org/protobuf/encoding/protojson"
)

const (
	// HandleMetrics -
	HandleMetrics = "metrics"

	// HandleHealthcheck -
	HandleHealthcheck = "healthcheck"

	// HandleDebug -
	HandleDebug = "debug"
)

func setupSgServer(ctx context.Context) (*server.APIServer, error) {
	var sgSrvOpts []sgroups.SGroupsServiceOpt
	if o, e := ServerAPIpathPrefix.Value(ctx); e == nil {
		sgSrvOpts = append(sgSrvOpts, sgroups.WithAPIpathPrefixes(o))
	} else if !errors.Is(e, config.ErrNotFound) {
		return nil, e
	}
	srv := sgroups.NewSGroupsService(ctx, getAppRegistry(), sgSrvOpts...)
	doc, err := sgroups.SecGroupSwaggerUtil.GetSpec()
	if err != nil {
		return nil, err
	}
	xOpt := server.WithGatewayOptions(
		runtime.WithMarshalerOption(runtime.MIMEWildcard, &runtime.JSONPb{
			MarshalOptions: protojson.MarshalOptions{
				EmitUnpopulated: true,
			},
			UnmarshalOptions: protojson.UnmarshalOptions{
				DiscardUnknown: false, //we fail when find unknown field in request
			},
		}),
	)
	opts := []server.APIServerOption{
		server.WithServices(srv),
		server.WithDocs(doc, ""),
		xOpt,
	}

	//если есть регистр Прометеуса то - подклчим метрики
	app.WhenHaveMetricsRegistry(func(reg *prometheus.Registry) {
		pm := serverPrometheusMetrics.NewMetrics(
			serverPrometheusMetrics.WithSubsystem("grpc"),
			serverPrometheusMetrics.WithNamespace("server"),
		)
		if err = reg.Register(pm); err != nil {
			return
		}
		recovery := interceptors.NewRecovery(
			interceptors.RecoveryWithObservers(pm.PanicsObserver()), //подключаем prometheus счетчик паник
		)
		//подключаем prometheus метрики
		opts = append(opts, server.WithRecovery(recovery))
		opts = append(opts, server.WithStatsHandlers(pm.StatHandlers()...))
		promHandler := promhttp.InstrumentMetricHandler(
			reg,
			promhttp.HandlerFor(reg, promhttp.HandlerOpts{}),
		)
		//экспанируем метрики через 'metrics' обработчик
		opts = append(opts, server.WithHttpHandler("/"+HandleMetrics, promHandler))
	})
	if err != nil {
		return nil, err
	}
	if hc, _ := HealthcheckEnable.Value(ctx); hc { // add healthcheck handler
		opts = append(opts, server.WithHttpHandler("/"+HandleHealthcheck, app.HcHandler{}))
	}
	opts = append(opts, server.WithHttpHandler("/"+HandleDebug, app.PProfHandler()))

	return server.NewAPIServer(opts...)
}
