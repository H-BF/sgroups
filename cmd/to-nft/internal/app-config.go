package internal

import (
	"time"

	"github.com/H-BF/sgroups/internal/config"
)

/*// config-sample.yaml

exit-on-success: true|false - do exit when we succeeded to apply netfilter config; def-val=false
netns: NetworkNS #is optional; def-val = ""
graceful-shutdown: 10s
base-rules:
  networks: ["10.10.1.0/24", "10.10.2.0/24",....]  # optional or value will borrow data from "extapi/svc/sgroups/address"
logger:
  level: INFO
dns:
  nameservers: ["8.8.8.8", "1.1.1.1", "...", ] #default ["8.8.8.8"]
  proto: tcp|udp #default udp
  port: 53 #default 53
  dial-duration: 3s #default 3s
  read-duration: 5s #default 5s
  write-duration: 5s #default 5s
  retries: 5 #default 1
  retry-timeout: 3s #default 1s

extapi:
  svc:
    def-daial-duration: 10s
    sgroups:
      dial-duration: 3s #override default-connect-tmo
      address: tcp://127.0.0.1:9006
	  sync-status:
        interval: 20s #mandatory
        push: true

telemetry:
  useragent: "string"
  endpoint: 127.0.0.1:5000
  metrics:
    enable: true
  healthcheck:
    enable: true
*/

const (

	// ExitOnSuccess do exit when we succeeded to apply netfilter config; def-val=false
	ExitOnSuccess config.ValueT[bool] = "exit-on-success"

	// ContinueOnFailure -
	ContinueOnFailure config.ValueT[bool] = "continue-on-failure"

	// AppLoggerLevel log level [optional]
	AppLoggerLevel config.ValueT[string] = "logger/level"
	// AppGracefulShutdown [optional]
	AppGracefulShutdown config.ValueT[time.Duration] = "graceful-schutdown"
	// NetNS network namespace
	NetNS config.ValueT[string] = "netns"

	// BaseRulesOutNets represents always list open networks for outgoing requests
	BaseRulesOutNets config.ValueT[[]config.NetCIDR] = "base-rules/networks"

	// DnsNameservers IP list of trusted nameservers; default = ["8.8.8.8"]
	DnsNameservers config.ValueT[[]config.IP] = "dns/nameservers"
	// DnsProto tcp or udp protp we shoud use; default = udp
	DnsProto config.ValueT[string] = "dns/proto"
	// DnsPort use port to ask nameserver(s); default = 53
	DnsPort config.ValueT[uint16] = "dns/port"
	// DnsRetries on failure retries count; default=3
	DnsRetries config.ValueT[uint8] = "dns/retries"
	// DnsRetriesTmo timeout before retry; default=1s
	DnsRetriesTmo config.ValueT[time.Duration] = "dns/retry-timeout"
	// DnsDialDuration dial max duration; default = 3s
	DnsDialDuration config.ValueT[time.Duration] = "dns/dial-duration"
	// DnsWriteDuration packet write max duration; default = 5s
	DnsWriteDuration config.ValueT[time.Duration] = "dns/write-duration"
	// DnsReadDuration response wait+read max duration; default = 5s
	DnsReadDuration config.ValueT[time.Duration] = "dns/read-duration"

	// ServicesDefDialDuration default dial duraton to conect a service [optional]
	ServicesDefDialDuration config.ValueT[time.Duration] = "extapi/svc/def-daial-duration"

	//SGroupsAddress service address [mandatory]
	SGroupsAddress config.ValueT[string] = "extapi/svc/sgroups/address"
	//SGroupsDialDuration sgroups service dial duration [optional]
	SGroupsDialDuration config.ValueT[time.Duration] = "extapi/svc/sgroups/dial-duration"
	//SGroupsSyncStatusInterval interval(duration) backend 'sync-status' check [mandatory]
	SGroupsSyncStatusInterval config.ValueT[time.Duration] = "extapi/svc/sgroups/sync-status/interval"
	//SGroupsSyncStatusPush use push model of 'sync-status'
	SGroupsSyncStatusPush config.ValueT[bool] = "extapi/svc/sgroups/sync-status/push"

	// TelemetryEndpoint server endpoint
	TelemetryEndpoint config.ValueT[string] = "telemetry/endpoint"
	// MetricsEnable enable api metrics
	MetricsEnable config.ValueT[bool] = "telemetry/metrics/enable"
	// HealthcheckEnable enables|disables health check handler
	HealthcheckEnable config.ValueT[bool] = "telemetry/healthcheck/enable"
	// UserAgent
	UserAgent config.ValueT[string] = "telemetry/useragent"
)
