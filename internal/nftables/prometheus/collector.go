package metrics

import (
	"context"
	"sync"
	"time"

	"github.com/H-BF/corlib/logger"
	conf "github.com/H-BF/corlib/pkg/nftables"
	"github.com/prometheus/client_golang/prometheus"
)

// NewCollector - impl prometheus.Collector
func NewCollector(ctx context.Context, p NFTConfReader, opts ...Opt) prometheus.Collector {
	const (
		minFreq = time.Second
	)
	ret := &nftCollector{
		ctx:             ctx,
		nftConfProvider: p,
		cached: cahcedMetrics{
			Mutex: new(sync.Mutex),
		},
	}
	for i := range opts {
		opts[i].apply(ret)
	}
	if ret.minRefreshFreq < minFreq {
		ret.minRefreshFreq = minFreq
	}
	return ret
}

// Opt -
type Opt interface {
	apply(*nftCollector)
}

// WithLogger -
func WithLogger(l logger.TypeOfLogger) Opt {
	return optFunc(func(c *nftCollector) {
		c.log = &l
	})
}

// WithMinFrequency -
func WithMinFrequency(d time.Duration) Opt {
	return optFunc(func(c *nftCollector) {
		c.minRefreshFreq = d
	})
}

// NFTConfReader -
type NFTConfReader interface {
	Fetch(context.Context) (conf.StateOfNFTables, error)
}

type optFunc func(*nftCollector)

// nftCollector - collects rules and counters from nftables using netlink
type nftCollector struct {
	ctx             context.Context
	nftConfProvider NFTConfReader
	log             *logger.TypeOfLogger
	minRefreshFreq  time.Duration

	cached cahcedMetrics
}

type cahcedMetrics struct {
	*sync.Mutex
	at      *time.Time
	metrics []prometheus.Metric
}

var _ prometheus.Collector = (*nftCollector)(nil)

// Describe - implements `prometheus.Collector`
func (c *nftCollector) Describe(ch chan<- *prometheus.Desc) {
	descs := [...]*prometheus.Desc{
		upDesc,
		counterBytesDesc,
		counterPacketsDesc,
		tableChainsDesc,
		chainRulesDesc,
		ruleBytesDesc,
		rulePacketsDesc,
	}
	for i := range descs {
		select {
		case <-c.ctx.Done():
			return
		case ch <- descs[i]:
		}
	}
}

// Collect - implements `prometheus.Collector`
func (c *nftCollector) Collect(ch chan<- prometheus.Metric) {
	mets := c.gather()
	for i := range mets {
		select {
		case <-c.ctx.Done():
			return
		case ch <- mets[i]:
		}
	}
}

func (c *nftCollector) gather() []prometheus.Metric {
	c.cached.Lock()
	defer c.cached.Unlock()
	if c.cached.at == nil || time.Since(*c.cached.at) >= c.minRefreshFreq {
		at := time.Now()
		v := float64(1)
		var mets []prometheus.Metric
		cnf, err := c.nftConfProvider.Fetch(c.ctx)
		if err != nil {
			c.logErr("on fetch 'nftables' state: %v", err)
			v = 0
		} else if mets, err = state2MetricsView(cnf); err != nil {
			c.logErr("on construct metrics view: %v", err)
			v, mets = 0, nil
		}
		c.cached.at = &at
		c.cached.metrics = append(
			mets, prometheus.MustNewConstMetric(upDesc, prometheus.GaugeValue, v),
		)
	}
	return c.cached.metrics
}

func (c *nftCollector) logErr(fmtMsg string, args ...any) {
	if c.log != nil {
		c.log.Errorf(fmtMsg, args...)
	}
}

func (o optFunc) apply(c *nftCollector) {
	o(c)
}
