package jobs

import "github.com/H-BF/corlib/pkg/patterns/observer"

// Option -
type Option interface {
	isOption()
}

// WithAgentSubject -
type WithAgentSubject struct {
	observer.Subject
}

func (WithAgentSubject) isOption() {}
