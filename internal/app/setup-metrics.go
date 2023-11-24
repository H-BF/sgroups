package app

import (
	"sync/atomic"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
)

type ( // options
	// SetupMetricsOpt -
	SetupMetricsOpt interface {
		isMetricOp()
	}

	// AddMetrics -
	AddMetrics struct {
		Metrics []prometheus.Collector
	}

	// NoStandardMetrics -
	NoStandardMetrics struct{}
)

var appPromRegistry atomic.Value

// SetupMetrics -
func SetupMetrics(opts ...SetupMetricsOpt) error {
	reg := prometheus.NewRegistry()
	var noDefGoMetrics bool
	var collectors []prometheus.Collector
	for _, o := range opts {
		switch v := o.(type) {
		case NoStandardMetrics:
			noDefGoMetrics = true
		case AddMetrics:
			collectors = append(collectors, v.Metrics...)
		}
	}
	if !noDefGoMetrics {
		collectors = append(collectors, StandardMetrics()...)
	}
	for _, c := range collectors {
		if err := reg.Register(c); err != nil {
			return err
		}
	}
	appPromRegistry.Store(reg)
	return nil
}

// StandardMetrics добавим гошные + системные коллекторы
func StandardMetrics() []prometheus.Collector {
	return []prometheus.Collector{
		//collectors.NewBuildInfoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		collectors.NewGoCollector(),
	}
}

// WhenHaveMetricsRegistry ...
func WhenHaveMetricsRegistry(f func(reg *prometheus.Registry)) {
	r, _ := appPromRegistry.Load().(*prometheus.Registry)
	if r != nil && f != nil {
		f(r)
	}
}

func (AddMetrics) isMetricOp()        {}
func (NoStandardMetrics) isMetricOp() {}
