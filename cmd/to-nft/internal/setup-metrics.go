package internal

import (
	"context"
	"os"

	"github.com/H-BF/sgroups/internal/app"
	nftablescollector "github.com/H-BF/sgroups/internal/nftables-collector"
	"github.com/H-BF/sgroups/pkg/atomic"

	"github.com/google/nftables"
	"github.com/prometheus/client_golang/prometheus"
)

type AgentMetrics struct {
	appliedConfigCount prometheus.Counter
	errorCount         *prometheus.CounterVec
}

var agentMetricsHolder atomic.Value[*AgentMetrics]

const (
	labelUserAgent = "user_agent"
	labelHostName  = "host_name"
	labelSource    = "source"
	nsAgent        = "agent"
)

const ( // error sources
	// ESrcDNS -
	ESrcDNS = "dns"

	// ESrcNetWatcher -
	ESrcNetWatcher = "net-watcher"

	// ESrcSgBakend -
	ESrcSgBakend = "sgroups-svc"
)

// SetupMetrics -
func SetupMetrics(ctx context.Context) error {
	if !MetricsEnable.MustValue(ctx) {
		return nil
	}

	nlConn, err := nftables.New()
	if err != nil {
		return err
	}

	dumpFile := NftablesCollectorDumpFile.MustValue(ctx)

	hostname, err := os.Hostname()
	if err != nil {
		return err
	}
	labels := prometheus.Labels{
		labelUserAgent: UserAgent.MustValue(ctx),
		labelHostName:  hostname,
	}
	am := new(AgentMetrics)
	am.init(labels)
	metricsOpt := app.AddMetrics{
		Metrics: []prometheus.Collector{
			&nftablescollector.NftCollector{Ctx: ctx, Conn: nlConn, Dump: dumpFile},
			app.NewHealthcheckMetric(labels),
			am.appliedConfigCount,
			am.errorCount,
		},
	}
	err = app.SetupMetrics(metricsOpt)
	if err == nil {
		agentMetricsHolder.Store(am, nil)
	}
	return err
}

// GetAgentMetrics -
func GetAgentMetrics() *AgentMetrics {
	v, _ := agentMetricsHolder.Load()
	return v
}

func (am *AgentMetrics) init(labels prometheus.Labels) {
	am.appliedConfigCount = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace:   nsAgent,
		Name:        "applied_configs",
		Help:        "count of successfully applied configurations",
		ConstLabels: labels,
	})
	am.errorCount = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace:   nsAgent,
		Name:        "errors",
		Help:        "count of errors",
		ConstLabels: labels,
	}, []string{labelSource})
}

// ObserveError -
func (am *AgentMetrics) ObserveError(errSource string) {
	am.errorCount.WithLabelValues(errSource).Inc()
}

// ObserveApplyConfig -
func (am *AgentMetrics) ObserveApplyConfig() {
	am.appliedConfigCount.Inc()
}
