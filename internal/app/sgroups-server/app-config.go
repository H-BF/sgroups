package server

import (
	"time"

	config "github.com/H-BF/corlib/pkg/plain-config"
)

/*//Sample of config
logger:
  level: INFO

metrics:
  enable: true

healthcheck:
  enable: true

server:
  endpoint: tcp://127.0.0.1:9006
  graceful-shutdown: 30s
  api-path-prefix: "static/path/prefix" #is empty by default

storage:
  type: <internal|postgres> ; 'internal' is by default
  postgres:
    url: postgres://un:psw@host/db
authn:
  type: <none|tls> #authentication type; `tls` is by default
  tls:
    key-file: "filename1.pem"
    cert-file: "filename2.pem"
    client:
      verify: <skip|certs-required|verify> # 'skip' is by default
      ca-files: ["file1.pem", "file2.pem", "file3.pem", ...]
*/

const (
	// LoggerLevel log level
	LoggerLevel config.ValueT[string] = "logger/level"

	// ServerEndpoint server endpoint
	ServerEndpoint config.ValueT[string] = "server/endpoint"

	// ServerGracefulShutdown graceful shutdown period
	ServerGracefulShutdown config.ValueT[time.Duration] = "server/graceful-shutdown"

	// ServerAPIpathPrefix is a path api prefix
	ServerAPIpathPrefix config.ValueT[string] = "server/api-path-prefix"

	// MetricsEnable enable api metrics
	MetricsEnable config.ValueT[bool] = "metrics/enable"

	// HealthcheckEnable enables|disables health check handler
	HealthcheckEnable config.ValueT[bool] = "healthcheck/enable"

	// StorageType selects storage DB backend
	StorageType config.ValueT[string] = "storage/type"

	// PostgresURL URL to connect Postgres DB
	PostgresURL config.ValueT[string] = "storage/postgres/url"

	//                    -= AuthnType =-
	// AuthnType selects authn type <none|tls> where `none` is by default
	AuthnType config.AuthnTypeSelector = "authn/type"
	//                    -= AUTHN/TLS =-
	// TLSprivKeyFile server private key PEM encoded file
	TLSprivKeyFile config.TLSprivKeyFile = "authn/tls/key-file"
	// TLScertFile server cert PEM encoded file
	TLScertFile config.TLScertFile = "authn/tls/cert-file"
	// TLSclientCAfiles client cert authority PEM files
	TLSclientCAfiles config.TLScaFiles = "authn/tls/client/ca-files"
	// TLSclientVerifyStrategy verify client and certs a.k.a MTLS; 'skip' is by default
	TLSclientVerifyStrategy config.TLSclientVerifyStrategy = "authn/tls/client/verify"
)
