package internal

import (
	"context"

	"github.com/H-BF/sgroups/internal/app"

	"github.com/H-BF/corlib/server"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// WhenSetupTelemtryServer -
func WhenSetupTelemtryServer(ctx context.Context, f func(*server.APIServer) error) error {
	var (
		opts []server.APIServerOption
		err  error
	)
	app.WhenHaveMetricsRegistry(func(reg *prometheus.Registry) {
		opts = append(opts,
			server.WithHttpHandler("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{Registry: reg})),
		)
	})
	if err != nil {
		return err
	}
	if hc, _ := HealthcheckEnable.Value(ctx); hc {
		opts = append(opts, server.WithHttpHandler("/healthcheck", app.BuildInfoHandler{}))
	}
	if len(opts) == 0 {
		return nil
	}
	var srv *server.APIServer
	if srv, err = server.NewAPIServer(opts...); err == nil {
		err = f(srv)
	}
	return err
}
