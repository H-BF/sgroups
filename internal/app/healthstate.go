package app

import (
	"bytes"
	"encoding/json"
	"net/http"
	"runtime"
	"sync/atomic"

	app_identity "github.com/H-BF/corlib/app/identity"
	"github.com/prometheus/client_golang/prometheus"
)

type (
	// BuildInfoHandler -
	BuildInfoHandler struct{}
)

var (
	healthState atomic.Bool
	bldInfo     = make(map[string]string)
)

func init() {
	healthState.Store(true)
	bldItem := []struct {
		name string
		val  string
	}{
		{"name", app_identity.Name},
		{"version", app_identity.Version},
		{"go_version", runtime.Version()},
		{"build_ts", app_identity.BuildTS},
		{"branch", app_identity.BuildBranch},
		{"hash", app_identity.BuildHash},
		{"tag", app_identity.BuildTag},
	}
	for _, n := range bldItem {
		if len(n.val) > 0 {
			bldInfo[n.name] = n.val
		}
	}
}

// SetHealthState -
func SetHealthState(state bool) {
	healthState.Store(state)
}

// NewHealthcheckMetric -
func NewHealthcheckMetric(withAdditionalLabels prometheus.Labels) prometheus.Collector {
	labs := make(map[string]string)
	for k, v := range bldInfo {
		labs[k] = v
	}
	for k, v := range withAdditionalLabels {
		if _, has := labs[k]; !has {
			labs[k] = v
		}
	}
	opts := prometheus.GaugeOpts{
		Name:        "healthcheck",
		Help:        "Healthcheck. Possible values: 0 or 1.",
		ConstLabels: labs,
	}
	return prometheus.NewGaugeFunc(opts, func() float64 {
		if healthState.Load() {
			return 1
		}
		return 0
	})
}

// ServeHTTP -
func (BuildInfoHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	nfo := struct {
		App     any
		Healthy bool
	}{bldInfo, healthState.Load()}
	w.Header().Add("Content-Type", "application/json")
	bt := bytes.NewBuffer(nil)
	if e := json.NewEncoder(bt).Encode(nfo); e != nil {
		w.WriteHeader(http.StatusInternalServerError)
	} else {
		_, _ = w.Write(bt.Bytes())
	}
}
