package patterns

import (
	"github.com/H-BF/corlib/pkg/atomic"
	"github.com/H-BF/corlib/pkg/patterns/observer"
)

type (
	// Observer is an alias
	Observer = observer.Observer

	// EventType is an alias
	EventType = observer.EventType

	// EventReceiver is an alias
	EventReceiver = observer.EventReceiver

	// Subject is an Subject pattern + Close method
	Subject interface {
		observer.Subject
		Close() error
	}
)

// NewSubject creates an Subject instance
func NewSubject() Subject {
	ret := new(closableSubject)
	ret.inner.Store(observer.NewSubject(), nil)
	return ret
}

// NewObserver -
var NewObserver = observer.NewObserver

type closableSubject struct {
	inner atomic.Value[observer.Subject]
}

var _ Subject = (*closableSubject)(nil)

// ObserversAttach impl Subject interface
func (sbj *closableSubject) ObserversAttach(obs ...Observer) {
	if s, ok := sbj.inner.Load(); ok {
		s.ObserversAttach(obs...)
	}
}

// ObserversDetach impl Subject interface
func (sbj *closableSubject) ObserversDetach(obs ...Observer) {
	if s, ok := sbj.inner.Load(); ok {
		s.ObserversDetach(obs...)
	}
}

// DetachAllObservers impl Subject interface
func (sbj *closableSubject) DetachAllObservers() {
	if s, ok := sbj.inner.Load(); ok {
		s.DetachAllObservers()
	}
}

// Notify impl Subject interface
func (sbj *closableSubject) Notify(evts ...EventType) {
	if s, ok := sbj.inner.Load(); ok {
		s.Notify(evts...)
	}
}

// Close detach all observers and destroy inner subject
func (sbj *closableSubject) Close() error {
	sbj.inner.Clear(func(s observer.Subject) {
		s.DetachAllObservers()
	})
	return nil
}
