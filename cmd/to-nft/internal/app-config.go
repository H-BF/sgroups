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

extapi:
  svc:
    def-daial-duration: 10s
    sgroups:
	  dial-duration: 3s #override default-connect-tmo
      address: tcp://127.0.0.1:9006
	  check-sync-status: 20s #mandatory
*/

const (

	// ExitOnSuccess do exit when we succeeded to apply netfilter config; def-val=false
	ExitOnSuccess config.ValueT[bool] = "exit-on-success"

	// AppLoggerLevel log level [optional]
	AppLoggerLevel config.ValueT[string] = "logger/level"
	// AppGracefulShutdown [optional]
	AppGracefulShutdown config.ValueT[time.Duration] = "graceful-schutdown"
	// NetNS network namespace
	NetNS config.ValueT[string] = "netns"

	// BaseRulesOutNets represents always list open networks for outgoing requests
	BaseRulesOutNets config.ValueT[[]config.NetCIDR] = "base-rules/networks"

	// ServicesDefDialDuration default dial duraton to conect a service [optional]
	ServicesDefDialDuration config.ValueT[time.Duration] = "extapi/svc/def-daial-duration"

	//SGroupsAddress service address [mandatory]
	SGroupsAddress config.ValueT[string] = "extapi/svc/sgroups/address"
	//SGroupsDialDuration sgroups service dial duration [optional]
	SGroupsDialDuration config.ValueT[time.Duration] = "extapi/svc/sgroups/dial-duration"
	//SGroupsSyncStatusInterval interval(duration) backend sync-status check [mandatory]
	SGroupsSyncStatusInterval config.ValueT[time.Duration] = "extapi/svc/sgroups/check-sync-status"
)
