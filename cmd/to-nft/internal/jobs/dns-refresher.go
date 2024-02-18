package jobs

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/H-BF/sgroups/cmd/to-nft/internal"
	"github.com/H-BF/sgroups/internal/dict"
	model "github.com/H-BF/sgroups/internal/models/sgroups"
	"github.com/H-BF/sgroups/internal/queue"

	"github.com/H-BF/corlib/logger"
	"github.com/H-BF/corlib/pkg/jsonview"
	"github.com/H-BF/corlib/pkg/patterns/observer"
	"github.com/c-robinson/iplib"
	"github.com/pkg/errors"
)

type (

	// Ask2ResolveDomainAddresses -
	Ask2ResolveDomainAddresses struct {
		IpVersion   int
		FQDN        model.FQDN
		ValidBefore time.Time

		observer.EventType
	}

	// DomainAddresses -
	DomainAddresses struct {
		IpVersion int
		FQDN      model.FQDN
		DnsAnswer internal.DomainAddresses

		observer.EventType
	}

	// DnsRefresher -
	DnsRefresher struct {
		agentSubj observer.Subject
		sema      chan struct{}
		close     chan struct{}
		stopped   chan struct{}
		onceClose sync.Once
		onceRun   sync.Once
	}
)

// NewDnsRefresher -
func NewDnsRefresher() *DnsRefresher {
	const semaphoreCap = 4

	ret := DnsRefresher{
		agentSubj: internal.AgentSubject(),
		sema:      make(chan struct{}, semaphoreCap),
		close:     make(chan struct{}),
	}
	for i := 0; i < cap(ret.sema); i++ {
		ret.sema <- struct{}{}
	}
	return &ret
}

// Close -
func (rf *DnsRefresher) Close() error {
	rf.onceClose.Do(func() {
		close(rf.close)
		rf.onceRun.Do(func() {})
		if rf.stopped != nil {
			<-rf.stopped
		}
	})
	return nil
}

// Run -
func (rf *DnsRefresher) Run(ctx context.Context) (err error) {
	var doRun bool
	rf.onceRun.Do(func() { doRun = true })
	if !doRun {
		return errors.New("it has been run or closed yet")
	}

	log := logger.FromContext(ctx).Named("dns").Named("refresher")
	log.Info("start")

	var activeQueries struct {
		sync.Mutex
		dict.RBDict[Ask2ResolveDomainAddresses, *time.Timer]
	}
	que := queue.NewFIFO()
	queObs := observer.NewObserver(func(ev observer.EventType) {
		_ = que.Put(ev)
	}, false, Ask2ResolveDomainAddresses{})
	rf.agentSubj.ObserversAttach(queObs)
	rf.stopped = make(chan struct{})
	defer func() {
		que.Close()
		rf.agentSubj.ObserversDetach(queObs)
		queObs.Close()
		activeQueries.Lock()
		activeQueries.Iterate(func(_ Ask2ResolveDomainAddresses, v *time.Timer) bool {
			_ = v.Stop()
			return true
		})
		activeQueries.Unlock()
		close(rf.stopped)
		log.Info("stop")
	}()
	for events := que.Reader(); ; {
		select {
		case <-ctx.Done():
			log.Info("will exit cause it has canceled")
			return ctx.Err()
		case <-rf.close:
			log.Infof("will exit cause it has closed")
			return nil
		case raw := <-events:
			switch ev := raw.(type) {
			case DomainAddresses:
				log1 := log.WithField("domain", ev.FQDN).WithField("IPv", ev.IpVersion)
				if e := ev.DnsAnswer.Err; e != nil {
					log1.Errorw("resolved", "error", jsonview.Stringer(e))
				} else {
					log1.Debugw("resolved",
						"TTL", jsonview.Stringer(ev.DnsAnswer.TTL.Round(time.Second)),
						"IP(s)", ev.DnsAnswer.IPs)
				}
				rf.agentSubj.Notify(ev)
			case Ask2ResolveDomainAddresses:
				activeQueries.Lock()
				if activeQueries.At(ev) == nil {
					now := time.Now()
					ttl := ev.ValidBefore.Sub(now)
					if ttl < time.Minute {
						ttl = time.Minute
					}
					log.Debugw("ask-to-resolve",
						"IPv", ev.IpVersion,
						"domain", jsonview.Stringer(ev.FQDN),
						"after", jsonview.Stringer(ttl.Round(time.Second)),
					)
					newTimer := time.AfterFunc(ttl, func() {
						select {
						case <-ctx.Done():
						case <-rf.close:
						case <-rf.sema:
							defer func() {
								rf.sema <- struct{}{}
							}()
							ret := rf.resolve(ctx, ev)
							que.Put(ret)
						}
						activeQueries.Lock()
						activeQueries.Del(ev)
						activeQueries.Unlock()
					})
					activeQueries.Put(ev, newTimer)
				}
				activeQueries.Unlock()
			}
		}
	}
}

func (rf *DnsRefresher) resolve(ctx context.Context, ask Ask2ResolveDomainAddresses) DomainAddresses {
	ret := DomainAddresses{
		IpVersion: ask.IpVersion,
		FQDN:      ask.FQDN,
	}
	resolver := internal.GetDnsResolver()
	domain := ask.FQDN.String()
	switch ask.IpVersion {
	case iplib.IP4Version:
		ret.DnsAnswer = resolver.A(ctx, domain)
	case iplib.IP6Version:
		ret.DnsAnswer = resolver.AAAA(ctx, domain)
	default:
		panic(
			fmt.Errorf("FqdnRefresher: passed unsupported IP version: %v'", ask.IpVersion),
		)
	}
	return ret
}

// Cmp -
func (a Ask2ResolveDomainAddresses) Cmp(other Ask2ResolveDomainAddresses) int {
	if a.IpVersion > other.IpVersion {
		return 1
	}
	if a.IpVersion < other.IpVersion {
		return -1
	}
	return a.FQDN.Cmp(other.FQDN)
}
