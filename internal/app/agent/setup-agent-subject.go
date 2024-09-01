package agent

import (
	"sync"

	"github.com/H-BF/corlib/pkg/atomic"
	"github.com/H-BF/corlib/pkg/patterns/observer"
	"github.com/H-BF/corlib/pkg/signals"
)

type ( // agent events
	// AgentSubjectClosed -
	AgentSubjectClosed struct{ observer.EventType }
)

// SetupAgentSubject -
func SetupAgentSubject() {
	setupSubjectOfAgentOnce.Do(func() {
		agentSubjectHolder.Store(&subjectOfAgent{
			Subject: observer.NewSubject(),
		}, nil)
		signals.WhenSignalExit(func() error {
			o, _ := agentSubjectHolder.Load()
			o.closed = true
			o.Notify(AgentSubjectClosed{})
			o.DetachAllObservers()
			return nil
		})
	})
}

// AgentSubject -
func AgentSubject() observer.Subject {
	ret, ok := agentSubjectHolder.Load()
	if !ok {
		panic("Need call 'SetupAgentSubject'")
	}
	return ret
}

type subjectOfAgent struct {
	closed bool
	observer.Subject
}

// ObserversAttach -
func (a *subjectOfAgent) ObserversAttach(obs ...observer.Observer) {
	if !a.closed {
		a.Subject.ObserversAttach(obs...)
	}
}

var (
	agentSubjectHolder      atomic.Value[*subjectOfAgent]
	setupSubjectOfAgentOnce sync.Once
)
