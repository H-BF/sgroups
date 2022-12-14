package main

import (
	"github.com/H-BF/sgroups/internal/config"
	"time"
)

/*//Sample of config
logger:
  level: INFO

metrics:
  enable: true

server:
  endpoint: tcp://127.0.0.1:9006
  graceful-shutdown: 30s
*/

const (
	//LoggerLevel log level
	LoggerLevel config.ValueT[string] = "logger/level"

	//ServerEndpoint server endpoint
	ServerEndpoint config.ValueT[string] = "server/endpoint"

	//ServerGracefulShutdown graceful shutdown period
	ServerGracefulShutdown config.ValueT[time.Duration] = "server/graceful-shutdown"

	//MetricsEnable enable api metrics
	MetricsEnable config.ValueT[bool] = "metrics/enable"
)
