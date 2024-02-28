package internal

import (
	"github.com/H-BF/corlib/pkg/patterns/observer"
)

// NewTiedSubj -
func NewTiedSubj(tied observer.Subject) observer.Subject {
	return &tiedSubject{
		Subject: observer.NewSubject(),
		tied:    tied,
	}
}

type tiedSubject struct {
	observer.Subject
	tied observer.Subject
}

var _ observer.Subject = (*tiedSubject)(nil)

// Notify impl observer.Subject iface
func (sb *tiedSubject) Notify(events ...observer.EventType) {
	sb.Subject.Notify(events...)
	sb.tied.Notify(events...)
}
