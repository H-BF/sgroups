package agent

import (
	"sync"

	"github.com/H-BF/sgroups/internal/app"
)

type hcIndicator uint8

const (
	// HcSyncStatus -
	HcSyncStatus hcIndicator = 1 << iota

	// HcNetConfWatcher -
	HcNetConfWatcher

	// HcDnsRefresher -
	HcDnsRefresher

	// HcNftApplier -
	HcNftApplier
)

var hcIndicators struct {
	sync.Mutex
	val uint8
}

// Set -
func (i hcIndicator) Set(val bool) {
	const healthy = uint8(
		HcSyncStatus | HcNetConfWatcher | HcDnsRefresher | HcNftApplier,
	)
	hcIndicators.Lock()
	defer hcIndicators.Unlock()
	if val {
		hcIndicators.val |= uint8(i)
	} else {
		hcIndicators.val &= ^uint8(i)
	}
	app.SetHealthState(healthy == hcIndicators.val)
}
