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
	// HcHandler -
	HcHandler struct{}
)

var (
	flagHealthy int32

	bldInfo = func() map[string]string {
		ret := make(map[string]string)
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
				ret[n.name] = n.val
			}
		}
		return ret
	}()
)

// SetHealthState -
func SetHealthState(state bool) {
	var st int32
	if state {
		st = 1
	}
	atomic.StoreInt32(&flagHealthy, st)
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
		Help:        "Healthcheck indicator(0 or 1)",
		ConstLabels: labs,
	}
	return prometheus.NewGaugeFunc(opts, func() float64 {
		return float64(atomic.AddInt32(&flagHealthy, 0))
	})
}

// ServeHTTP -
func (HcHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	nfo := struct {
		App     any  `json:"app,omitempty"`
		Healthy bool `json:"healthy"`
	}{bldInfo, atomic.AddInt32(&flagHealthy, 0) != 0}
	w.Header().Add("Content-Type", "application/json")
	bt := bytes.NewBuffer(nil)
	if e := json.NewEncoder(bt).Encode(nfo); e != nil {
		w.WriteHeader(http.StatusInternalServerError)
	} else {
		_, _ = w.Write(bt.Bytes())
	}
}
