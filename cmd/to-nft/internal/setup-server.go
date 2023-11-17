package internal

import (
	"context"

	"github.com/H-BF/sgroups/cmd/to-nft/internal/metrics"
	"github.com/H-BF/sgroups/internal/app"

	pkgNet "github.com/H-BF/corlib/pkg/net"
	"github.com/H-BF/corlib/server"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func SetupServer(ctx context.Context) (*server.APIServer, error) {
	var (
		opts []server.APIServerOption
		err  error
	)
	app.WhenHaveMetricsRegistry(func(reg *prometheus.Registry) {
		constMetrics := []prometheus.Collector{
			app.NewHealthcheckMetric(),
		}
		for _, m := range constMetrics {
			if err = reg.Register(m); err != nil {
				return
			}
		}

		var (
			addr       string
			appMetrics metrics.AppMetrics
		)
		addr, err = SGroupsAddress.Value(ctx)
		if err != nil {
			return
		}
		var ep *pkgNet.Endpoint
		if ep, err = pkgNet.ParseEndpoint(addr); err != nil {
			return
		}
		appMetrics, err = metrics.NewAppMetrics(reg, ep)
		if err != nil {
			return
		}
		AgentSubject().ObserversAttach(appMetrics)

		opts = append(opts,
			server.WithHttpHandler("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{Registry: reg})),
		)
	})
	if err != nil {
		return nil, err
	}

	if hc, _ := HealthcheckEnable.Value(ctx); hc {
		opts = append(opts, server.WithHttpHandler("/healthcheck", app.GetHCHandler()))
	}
	if err != nil {
		return nil, err
	}
	return server.NewAPIServer(opts...)
}
