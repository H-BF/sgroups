package main

import (
	"context"

	"github.com/H-BF/corlib/server"
	"github.com/H-BF/corlib/server/interceptors"
	serverPrometheusMetrics "github.com/H-BF/corlib/server/metrics/prometheus"
	"github.com/H-BF/sgroups/internal/api/sgroups"
	"github.com/H-BF/sgroups/internal/app"
	registry "github.com/H-BF/sgroups/internal/registry/sgroups"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func setupSgServer(ctx context.Context) (*server.APIServer, error) {
	var reg registry.Registry
	{
		m, e := registry.NewMemDB(registry.TblSecGroups,
			registry.TblSecRules, registry.TblNetworks,
			registry.IntegrityChecker4SG(),
			registry.IntegrityChecker4Rules())
		if e != nil {
			return nil, errors.WithMessage(e, "create mem db")
		}
		reg = registry.NewRegistryFromMemDB(m)
	}
	srv := sgroups.NewSGroupsService(ctx, reg)
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
		//экспанируем метрики через '/metrics' обработчик
		opts = append(opts, server.WithHttpHandler("/metrics", promHandler))
	})
	if err != nil {
		return nil, err
	}
	opts = append(opts, server.WithHttpHandler("/debug", app.PProfHandler()))
	return server.NewAPIServer(opts...)
}
