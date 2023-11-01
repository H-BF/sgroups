package internal

import (
	"context"
	"net/http"

	"github.com/H-BF/corlib/server"
	"github.com/H-BF/sgroups/internal/app"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func SetupServer(ctx context.Context) (*server.APIServer, error) {
	var (
		opts []server.APIServerOption
		err  error
	)
	app.WhenHaveMetricsRegistry(func(reg *prometheus.Registry) {
		err = reg.Register(app.NewHealthcheckMetric(prometheus.GaugeOpts{
			Name: "healthcheck",
			ConstLabels: map[string]string{
				"name":       "agent",
				"version":    "версия продукта",
				"go_version": "(go версия)",
				"build_ts":   "время сборки",
				"branch":     "git ветка",
				"hash":       "git hash",
				"tag":        "some tag",
			},
		}))
		if err != nil {
			return
		}
		opts = append(opts,
			server.WithHttpHandler("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{Registry: reg})),
		)
	})

	if hc, _ := HealthcheckEnable.Value(ctx); hc {
		healthcheck := func(w http.ResponseWriter, r *http.Request) {
			w.Header().Add("Content-Type", "application/json")
			_, _ = w.Write([]byte("{}"))
		}
		opts = append(opts, server.WithHttpHandler("/healthcheck", http.HandlerFunc(healthcheck)))
	}
	if err != nil {
		return nil, err
	}
	return server.NewAPIServer(opts...)
}
