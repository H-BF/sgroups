package agent

import (
	"strings"
	"time"

	config "github.com/H-BF/corlib/pkg/plain-config"
)

/*// config-sample.yaml

exit-on-success: true|false - do exit when we succeeded to apply netfilter config; def-val=false
netns: NetworkNS #is optional; def-val = ""
graceful-shutdown: 10s
base-rules:
  networks: ["10.10.1.0/24", "10.10.2.0/24",....]  # optional or value will borrow data from "extapi/svc/sgroups/address"
fqdn-rules:
  strategy: dns #default = dns
logger:
  level: INFO
netlink:
  watcher: #netlink watcher
    linger: 10s
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
      use-json-codec: <true|false> # = false by default
      api-path-prefix: "a/b/c" # = is not set by default
      authn:
        type: <none|tls> # 'none' is by default
        tls:
          key-file: "key-file.pem"
          cert-file: "cert-file.pem"
          server:
            verify: <true|false> # false is by default
            name: "server-name" # is not present by default
            ca-files: ["file1.pem", "file2.pem", ...] # is not present by default

telemetry:
  useragent: "string"
  nft-collector:
    min-frequency: 1s
  endpoint: 127.0.0.1:5000
  metrics:
    enable: true
  healthcheck:
    enable: true
  profile:
    enable: true
*/

const (

	// ExitOnSuccess do exit when we succeeded to apply netfilter config; def-val=false
	ExitOnSuccess config.ValueT[bool] = "exit-on-success"

	// ContinueOnFailure (default = true)
	// when 'true' it means if something fails it internally restarts all workloads after some tomeout
	// when 'false' if something fails the app exits with code 1
	ContinueOnFailure config.ValueT[bool] = "continue-on-failure"

	// ContinueAfterTimeout (default = '10s' )
	// if 'continue-on-failure'=true then we use this value to do timeout befor restart
	ContinueAfterTimeout config.ValueT[time.Duration] = "continue-after-timeout"

	// AppLoggerLevel log level [optional]
	AppLoggerLevel config.ValueT[string] = "logger/level"
	// AppGracefulShutdown [optional]
	AppGracefulShutdown config.ValueT[time.Duration] = "graceful-schutdown"
	// NetNS network namespace
	NetNS config.ValueT[string] = "netns"

	// NetlinkWatcherLinger netlingk watched linger duration, min(1s)
	NetlinkWatcherLinger config.ValueT[time.Duration] = "netlink/watcher/linger"

	// BaseRulesOutNets represents always list open networks for outgoing requests
	BaseRulesOutNets config.ValueT[[]config.NetCIDR] = "base-rules/networks"

	// FqdnStrategy use strategy to build SG-FQDN rules (DNS|NDPI|Combine); DNS is default
	FqdnStrategy config.ValueT[FqdnRulesStrategy] = "fqdn-rules/strategy"

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

	//                         -= extapi/svc/ SGROUPS =-
	//SGroupsAddress service address [mandatory]
	SGroupsAddress config.ValueT[string] = "extapi/svc/sgroups/address"
	//SGroupsDialDuration sgroups service dial duration [optional]
	SGroupsDialDuration config.ValueT[time.Duration] = "extapi/svc/sgroups/dial-duration"
	//SGroupsSyncStatusInterval interval(duration) backend 'sync-status' check [mandatory]
	SGroupsSyncStatusInterval config.ValueT[time.Duration] = "extapi/svc/sgroups/sync-status/interval"
	//SGroupsSyncStatusPush use push model of 'sync-status'
	SGroupsSyncStatusPush config.ValueT[bool] = "extapi/svc/sgroups/sync-status/push"
	// SGroupsUseJsonCodec use GRPC+JSON codec instead of GRPC+PROTO
	SGroupsUseJsonCodec config.ValueT[bool] = "extapi/svc/sgroups/use-json-codec"
	// SGroupsAPIpathPrefix add path prefix when call SGROUPS API - is not set by default
	SGroupsAPIpathPrefix config.ValueT[string] = "extapi/svc/sgroups/api-path-prefix"

	//                         -= extapi/svc/ SGROUPS/AUTHN =-
	SGroupsAuthnType config.AuthnTypeSelector = "extapi/svc/sgroups/authn/type"
	//                         -= extapi/svc/ SGROUPS/AUTHN/TLS =-
	// SGroupsTLScertFile client cert file
	SGroupsTLScertFile config.TLScertFile = "extapi/svc/sgroups/authn/tls/cert-file"
	// SGroupsTLSprivKeyFile client private key
	SGroupsTLSprivKeyFile config.TLScertFile = "extapi/svc/sgroups/authn/tls/key-file"
	// SGroupsTLSserverVerify if true we need verify server host or IPs
	SGroupsTLSserverVerify config.ValueT[bool] = "extapi/svc/sgroups/authn/tls/server/verify"
	// SGroupsTLSserverName server hostname we need to verify - not set by default
	SGroupsTLSserverName config.TLSverifysServerName = "extapi/svc/sgroups/authn/tls/server/name"
	// SGroupsTLSserverCAs server CA files
	SGroupsTLSserverCAs config.TLScaFiles = "extapi/svc/sgroups/authn/tls/server/ca-files"

	// TelemetryEndpoint server endpoint
	TelemetryEndpoint config.ValueT[string] = "telemetry/endpoint"
	// MetricsEnable enable api metrics
	MetricsEnable config.ValueT[bool] = "telemetry/metrics/enable"
	// HealthcheckEnable enables|disables health check handler
	HealthcheckEnable config.ValueT[bool] = "telemetry/healthcheck/enable"
	// UserAgent
	UserAgent config.ValueT[string] = "telemetry/useragent"
	// ProfileEnable available at /debug/pprof/index
	ProfileEnable config.ValueT[bool] = "telemetry/profile/enable"
	// NftablesCollectorMinFrequency states how often to update cache with nft metrics
	NftablesCollectorMinFrequency config.ValueT[time.Duration] = "telemetry/nft-collector/min-frequency"
)

type FqdnRulesStrategy string

// Eq -
func (o FqdnRulesStrategy) Eq(other FqdnRulesStrategy) bool {
	return strings.EqualFold(string(o), string(other))
}

// Variants -
func (FqdnRulesStrategy) Variants() []FqdnRulesStrategy {
	r := [...]FqdnRulesStrategy{
		FqdnRulesStartegyDNS, //FqdnRulesStartegyNDPI, FqdnRulesStartegyCombine,
	}
	return r[:]
}

const (
	// FqdnRulesStartegyDNS -
	FqdnRulesStartegyDNS FqdnRulesStrategy = "dns"
	// FqdnRulesStartegyNDPI -
	//FqdnRulesStartegyNDPI FqdnRulesStrategy = "ndpi"
	// FqdnRulesStartegyCombine -
	//FqdnRulesStartegyCombine FqdnRulesStrategy = "combine"
)
