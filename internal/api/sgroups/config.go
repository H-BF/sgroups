package sgroups

import (
	"github.com/H-BF/sgroups/internal/config"
	"time"
)

const (
	// UpdatePeriod interval for checking updates in DB
	UpdatePeriod config.ValueT[time.Duration] = "api/sgroups/update-period"
)
