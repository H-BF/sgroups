package internal

import (
	"sync"

	"github.com/H-BF/sgroups/internal/app"
)

type hcIndicator uint8

const (
	// HcSyncStatus -
	HcSyncStatus hcIndicator = 1 << iota

	// HcMainJob -
	HcMainJob
)

var (
	hcIndicators uint8
	chMX         sync.Mutex
)

// Set -
func (i hcIndicator) Set(val bool) {
	const healthy = uint8(HcSyncStatus | HcMainJob)
	chMX.Lock()
	defer chMX.Unlock()
	if val {
		hcIndicators |= uint8(i)
	} else {
		hcIndicators &= ^uint8(i)
	}
	app.SetHealthState(healthy == hcIndicators)
}
