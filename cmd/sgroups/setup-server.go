package main

import (
	"context"
	"net/http"

	"github.com/H-BF/sgroups/internal/api/sgroups"
	"github.com/H-BF/sgroups/internal/app"

	"github.com/H-BF/corlib/server"
	"github.com/H-BF/corlib/server/interceptors"
	serverPrometheusMetrics "github.com/H-BF/corlib/server/metrics/prometheus"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
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
	srv := sgroups.NewSGroupsService(ctx, getAppRegistry())
	doc, err := sgroups.SecGroupSwaggerUtil.GetSpec()
	if err != nil {
		return nil, err
	}
	opts := []server.APIServerOption{
		server.WithServices(srv),
		server.WithDocs(doc, ""),
	}

	//если есть регистр Прометеуса то - подклчим метрики
	WhenHaveMetricsRegistry(func(reg *prometheus.Registry) {
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
		h := http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			writer.Header().Add("Content-Type", "application/json")
			_, _ = writer.Write([]byte("{}"))
		})
		opts = append(opts, server.WithHttpHandler("/"+HandleHealthcheck, h))
	}
	opts = append(opts, server.WithHttpHandler("/"+HandleDebug, app.PProfHandler()))
	return server.NewAPIServer(opts...)
}
