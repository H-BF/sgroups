package dns

import (
	"time"

	bkf "github.com/H-BF/corlib/pkg/backoff"
)

// Option -
type Option interface {
	apply(*queryHelper)
}

type ( // options
	// UsePort -
	UsePort uint16

	// WithNameservers -
	WithNameservers []string

	// FromLocalAddr -
	FromLocalAddr string

	// WithDialDuration -
	WithDialDuration time.Duration

	// WithReadDuration -
	WithReadDuration time.Duration

	// WithWriteDuration -
	WithWriteDuration time.Duration

	// UseTCP -
	UseTCP struct{}

	// NoDefNS -
	NoDefNS struct{}

	// WithBackoff -
	WithBackoff struct {
		bkf.Backoff
	}
)

func (o UsePort) apply(r *queryHelper) {
	r.port = uint16(o)
}

func (o WithNameservers) apply(r *queryHelper) {
	r.nameservers = append([]string{}, o...)
}

func (o FromLocalAddr) apply(r *queryHelper) {
	r.localAddr = string(o)
}

func (o WithDialDuration) apply(r *queryHelper) {
	r.dialDuration = time.Duration(o)
}

func (o WithReadDuration) apply(r *queryHelper) {
	r.readDuration = time.Duration(o)
}

func (o WithWriteDuration) apply(r *queryHelper) {
	r.writeDuration = time.Duration(o)
}

func (o UseTCP) apply(r *queryHelper) {
	r.useTCP = true
}

func (o NoDefNS) apply(r *queryHelper) {
	r.noDefNS = true
}

func (o WithBackoff) apply(r *queryHelper) {
	if o.Backoff != nil {
		r.backoff = o.Backoff
	}
}
