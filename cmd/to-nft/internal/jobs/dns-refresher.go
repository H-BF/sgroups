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
		subject       observer.Subject
		sema          chan struct{}
		stopped       chan struct{}
		onceClose     sync.Once
		onceRun       sync.Once
		que           queue.FIFO[DomainAddresses]
		activeQueries struct {
			sync.Mutex
			closed bool
			dict.RBDict[Ask2ResolveDomainAddresses, *time.Timer]
		}
	}
)

// NewDnsRefresher -
func NewDnsRefresher(sbj observer.Subject) *DnsRefresher {
	const semaphoreCap = 4

	ret := DnsRefresher{
		subject: sbj,
		sema:    make(chan struct{}, semaphoreCap),
		que:     queue.NewFIFO[DomainAddresses](),
	}
	for i := 0; i < cap(ret.sema); i++ {
		ret.sema <- struct{}{}
	}
	return &ret
}

// MakeObserver -
func (rf *DnsRefresher) MakeObserver(ctx context.Context) observer.Observer {
	return observer.NewObserver(func(ev observer.EventType) {
		switch o := ev.(type) {
		case Ask2ResolveDomainAddresses:
			rf.onAsk2ResolveDomainAddresses(ctx, o)
		}
	}, false, Ask2ResolveDomainAddresses{})
}

// Close -
func (rf *DnsRefresher) Close() error {
	rf.onceClose.Do(func() {
		_ = rf.que.Close()
		rf.onceRun.Do(func() {})
		rf.activeQueries.Lock()
		rf.activeQueries.closed = true
		rf.activeQueries.Iterate(func(_ Ask2ResolveDomainAddresses, v *time.Timer) bool {
			_ = v.Stop()
			return true
		})
		rf.activeQueries.Unlock()
		if rf.stopped != nil {
			<-rf.stopped
		}
	})
	return nil
}

// Run -
func (rf *DnsRefresher) Run(ctx context.Context) (err error) {
	const job = "dns-refresher"

	var doRun bool
	rf.onceRun.Do(func() {
		doRun = true
		rf.stopped = make(chan struct{})
	})
	if !doRun {
		return errors.Errorf("%s: it has been run or closed yet", job)
	}

	log := logger.FromContext(ctx).Named(job)
	log.Info("start")
	defer func() {
		close(rf.stopped)
		log.Info("stop")
	}()
	for events := rf.que.Reader(); ; {
		select {
		case <-ctx.Done():
			log.Info("will exit cause it has canceled")
			return ctx.Err()
		case ev, ok := <-events:
			if !ok {
				log.Infof("will exit cause it has closed")
				return nil
			}
			log1 := log.WithField("domain", ev.FQDN).WithField("IPv", ev.IpVersion)
			if e := ev.DnsAnswer.Err; e != nil {
				log1.Errorw("resolved", "error", jsonview.Stringer(e))
			} else {
				log1.Debugw("resolved",
					"TTL", jsonview.Stringer(ev.DnsAnswer.TTL.Round(time.Second)),
					"IP(s)", ev.DnsAnswer.IPs)
			}
			rf.subject.Notify(ev)
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

func (rf *DnsRefresher) onAsk2ResolveDomainAddresses(ctx context.Context, ev Ask2ResolveDomainAddresses) {
	log := logger.FromContext(ctx)
	rf.activeQueries.Lock()
	defer rf.activeQueries.Unlock()
	if rf.activeQueries.At(ev) != nil || rf.activeQueries.closed {
		return
	}

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
		case <-rf.sema:
			defer func() {
				rf.sema <- struct{}{}
			}()
			ret := rf.resolve(ctx, ev)
			rf.que.Put(ret)
		}
		rf.activeQueries.Lock()
		defer rf.activeQueries.Unlock()
		rf.activeQueries.Del(ev)
	})
	rf.activeQueries.Put(ev, newTimer)
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
