package app

import (
	"sync/atomic"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
)

var appPromRegistry atomic.Value

func SetupMetrics(enabled bool) error {
	var reg *prometheus.Registry
	if enabled {
		reg = prometheus.NewRegistry()
		//добавим по умолчанию гошные + системные коллекторы
		cols := []prometheus.Collector{
			collectors.NewBuildInfoCollector(),
			collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
			collectors.NewGoCollector(),
		}
		for _, c := range cols {
			if err := reg.Register(c); err != nil {
				return err
			}
		}
	}
	appPromRegistry.Store(reg)
	return nil
}

// WhenHaveMetricsRegistry ...
func WhenHaveMetricsRegistry(f func(reg *prometheus.Registry)) {
	r, _ := appPromRegistry.Load().(*prometheus.Registry)
	if r != nil && f != nil {
		f(r)
	}
}
