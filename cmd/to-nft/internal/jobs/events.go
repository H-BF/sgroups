package jobs

import (
	"github.com/H-BF/corlib/pkg/patterns/observer"
	"github.com/H-BF/sgroups/cmd/to-nft/internal/host"
	"github.com/H-BF/sgroups/cmd/to-nft/internal/nft"
	uuid "github.com/satori/go.uuid"
)

// AppliedConfEvent -
type AppliedConfEvent struct {
	UID          uuid.UUID
	NetConf      host.NetConf
	AppliedRules nft.AppliedRules

	observer.EventType
}
