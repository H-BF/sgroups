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
		appliedConfigs   prometheus.Counter
		netlinkErr       prometheus.Counter
		syncStatusErr    prometheus.Counter
		fqdnRefresherErr prometheus.Counter
		nftApplierErr    prometheus.Counter
	}
)

const (
	MeasureType_Applied_Configs = iota

	// Errors
	MeasureType_Netlink_Err
	MeasureType_SyncStatus_Err
	MeasureType_FqdnRefresher_Err
	MeasureType_NftApplier_Err
)

var (
	AppliedConfigsInc   = MeasureEvent{mType: MeasureType_Applied_Configs}
	NetlinkErrInc       = MeasureEvent{mType: MeasureType_Netlink_Err}
	SyncStatusErrInc    = MeasureEvent{mType: MeasureType_SyncStatus_Err}
	FqdnRefresherErrInc = MeasureEvent{mType: MeasureType_FqdnRefresher_Err}
	NftApplierErrInc    = MeasureEvent{mType: MeasureType_NftApplier_Err}
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
			Namespace: ns,
			Subsystem: nftApplierSubsystem,
			Name:      "applied_configs",
			Help:      "Count of successfuly applied configurations",
			ConstLabels: map[string]string{
				"remote_address":   outIP.String(),
				"remote_host_name": hostname,
			},
		}),

		netlinkErr: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: ns,
			Subsystem: "netlink",
			Name:      "errors",
			Help:      "Count of errors received from NetlinkWatcher",
			ConstLabels: map[string]string{
				"remote_address":   outIP.String(),
				"remote_host_name": hostname,
			},
		}),

		syncStatusErr: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: ns,
			Subsystem: "syncstatus",
			Name:      "errors",
			Help:      "Count of errors received from grpc call while updating SyncStatus",
			ConstLabels: map[string]string{
				"remote_address":   outIP.String(),
				"remote_host_name": hostname,
			},
		}),

		fqdnRefresherErr: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: ns,
			Subsystem: "fqdnrefresher",
			Name:      "errors",
			Help:      "Count of failed attempts to refresh fqdn",
			ConstLabels: map[string]string{
				"remote_address":   outIP.String(),
				"remote_host_name": hostname,
			},
		}),

		nftApplierErr: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: ns,
			Subsystem: nftApplierSubsystem,
			Name:      "errors",
			Help:      "Count of failed nft config modifications",
			ConstLabels: map[string]string{
				"remote_address":   outIP.String(),
				"remote_host_name": hostname,
			},
		}),
	}

	appMetrics.register(reg)

	appMetrics.Observer = patterns.NewObserver(appMetrics.ApplyMeasure, false, MeasureEvent{})
	return appMetrics, nil
}

func (m AppMetrics) register(reg *prometheus.Registry) {
	reg.Register(m.appliedConfigs)
	reg.Register(m.netlinkErr)
	reg.Register(m.syncStatusErr)
	reg.Register(m.fqdnRefresherErr)
	reg.Register(m.nftApplierErr)
}

func (m AppMetrics) ApplyMeasure(event patterns.EventType) {
	measureEvent := event.(MeasureEvent)
	switch measureEvent.mType {
	case MeasureType_Applied_Configs:
		m.appliedConfigs.Inc()
	case MeasureType_Netlink_Err:
		m.netlinkErr.Inc()
	case MeasureType_SyncStatus_Err:
		m.syncStatusErr.Inc()
	case MeasureType_FqdnRefresher_Err:
		m.fqdnRefresherErr.Inc()
	case MeasureType_NftApplier_Err:
		m.nftApplierErr.Inc()
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

const (
	ns                  = "agent"
	nftApplierSubsystem = "applier"
)
