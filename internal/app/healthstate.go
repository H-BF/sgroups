package app

import (
	"sync/atomic"

	"github.com/prometheus/client_golang/prometheus"
)

var healthState atomic.Bool

func init() {
	healthState.Store(true)
}

func SetHealthState(state bool) {
	healthState.Store(state)
}

func NewHealthcheckMetric(opts prometheus.GaugeOpts) prometheus.Collector {
	opts.Help = "Healthcheck. Possible values: 0 or 1."
	return prometheus.NewGaugeFunc(opts, func() float64 {
		if healthState.Load() {
			return 1
		}
		return 0
	})
}
