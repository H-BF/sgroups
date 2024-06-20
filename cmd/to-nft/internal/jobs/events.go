package jobs

import (
	"github.com/H-BF/sgroups/cmd/to-nft/internal/nft"

	"github.com/H-BF/corlib/pkg/host"
	"github.com/H-BF/corlib/pkg/patterns/observer"
)

// AppliedConfEvent -
type AppliedConfEvent struct {
	NetConf      host.NetConf
	AppliedRules nft.AppliedRules

	observer.EventType
}
