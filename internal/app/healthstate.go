package app

import (
	"encoding/json"
	"net/http"
	"runtime"
	"sync/atomic"

	app_identity "github.com/H-BF/corlib/app/identity"
	"github.com/prometheus/client_golang/prometheus"
)

type (
	BuildInfo struct {
		Name      string
		Version   string
		GoVersion string
		BuildTs   string
		Branch    string
		Hash      string
		Tag       string
	}
)

var (
	healthState atomic.Bool
	buildInfo   = BuildInfo{
		Name:      app_identity.Name,
		Version:   app_identity.Version,
		GoVersion: runtime.Version(),
		BuildTs:   app_identity.BuildTS,
		Branch:    app_identity.BuildBranch,
		Hash:      app_identity.BuildHash,
		Tag:       app_identity.BuildTag,
	}
)

func init() {
	healthState.Store(true)
}

func SetHealthState(state bool) {
	healthState.Store(state)
}

func NewHealthcheckMetric() prometheus.Collector {
	opts := prometheus.GaugeOpts{
		Name:        "healthcheck",
		Help:        "Healthcheck. Possible values: 0 or 1.",
		ConstLabels: buildInfo.toMap(),
	}
	return prometheus.NewGaugeFunc(opts, func() float64 {
		if healthState.Load() {
			return 1
		}
		return 0
	})
}

func GetHCHandler() http.Handler {
	return &buildInfo
}

func (bi *BuildInfo) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "application/json")
	json.NewEncoder(w).Encode(bi)
}

func (bi *BuildInfo) toMap() map[string]string {
	return map[string]string{
		"name":       bi.Name,
		"version":    bi.Version,
		"go_version": bi.GoVersion,
		"build_ts":   bi.BuildTs,
		"branch":     bi.Branch,
		"hash":       bi.Hash,
		"tag":        bi.Tag,
	}
}
