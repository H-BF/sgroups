package jobs

import (
	"github.com/H-BF/corlib/pkg/patterns/observer"
)

// Option -
type Option interface {
	isOption()
}

// WithSubject -
type WithSubject struct {
	observer.Subject
}

// WithNetNS -
type WithNetNS string

func (WithSubject) isOption() {}
func (WithNetNS) isOption()   {}
