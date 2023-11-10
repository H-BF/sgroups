package metrics

import (
	"net"
	"os"

	"github.com/H-BF/sgroups/internal/patterns"

	pkgNet "github.com/H-BF/corlib/pkg/net"
	"github.com/prometheus/client_golang/prometheus"
)

type (
	MeasureType uint32

	MeasureEvent struct {
		patterns.EventType
		mType MeasureType
	}

	AppMetrics struct {
		patterns.Observer
		appliedConfigs prometheus.Counter
	}
)

const (
	MeasureType_Applied_Configs = iota
)

var (
	AppliedConfigsInc = MeasureEvent{mType: MeasureType_Applied_Configs}
)

func NewAppMetrics(reg *prometheus.Registry, sgEp *pkgNet.Endpoint) (AppMetrics, error) {
	outIP, err := GetOutboundIP(sgEp)
	if err != nil {
		return AppMetrics{}, err
	}
	hostname, err := os.Hostname()
	if err != nil {
		return AppMetrics{}, err
	}

	appMetrics := AppMetrics{
		appliedConfigs: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "agent",
			Subsystem: "applier",
			Name:      "applied_configs",
			Help:      "Count of successfuly applied configurations",
			ConstLabels: map[string]string{
				"remote_address":   outIP.String(),
				"remote_host_name": hostname,
			},
		}),
	}

	reg.Register(appMetrics.appliedConfigs)

	appMetrics.Observer = patterns.NewObserver(appMetrics.ApplyMeasure, false, MeasureEvent{})
	return appMetrics, nil
}

func (m AppMetrics) ApplyMeasure(event patterns.EventType) {
	measureEvent := event.(MeasureEvent)
	switch measureEvent.mType {
	case MeasureType_Applied_Configs:
		m.appliedConfigs.Inc()
	}
}

// GetOutboundIP - Get preferred outbound ip to connect to ep
func GetOutboundIP(ep *pkgNet.Endpoint) (net.IP, error) {
	addr, err := ep.Address()
	if err != nil {
		return nil, err
	}
	conn, err := net.Dial(ep.Network(), addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.TCPAddr)

	return localAddr.IP, nil
}
