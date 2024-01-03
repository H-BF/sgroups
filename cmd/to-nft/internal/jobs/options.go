package jobs

import (
	"github.com/H-BF/corlib/pkg/patterns/observer"
	"github.com/H-BF/sgroups/cmd/to-nft/internal"
)

// Option -
type Option interface {
	isOption()
}

// WithAgentSubject -
type WithAgentSubject struct {
	observer.Subject
}

// WithDnsResolver -
type WithDnsResolver struct {
	DnsRes internal.DomainAddressQuerier
}

// WithNetNS -
type WithNetNS string

func (WithAgentSubject) isOption() {}
func (WithDnsResolver) isOption()  {}
func (WithNetNS) isOption()        {}
