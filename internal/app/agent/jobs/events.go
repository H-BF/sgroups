package jobs

import (
	"github.com/H-BF/sgroups/v2/internal/app/agent/nft"

	"github.com/H-BF/corlib/pkg/host"
	"github.com/H-BF/corlib/pkg/patterns/observer"
)

// AppliedConfEvent -
type AppliedConfEvent struct {
	NetConf      host.NetConf
	AppliedRules nft.AppliedRules

	observer.EventType
}
