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
		obs       observer.Observer
		agentSubj observer.Subject
		queue     *queue.FIFO
		sema      chan struct{}
		close     chan struct{}
		closeOnce sync.Once
	}
)

// NewDnsRefresher -
func NewDnsRefresher() *DnsRefresher {
	const semaphoreCap = 8

	ret := DnsRefresher{
		agentSubj: internal.AgentSubject(),
		sema:      make(chan struct{}, semaphoreCap),
		close:     make(chan struct{}),
		queue:     queue.NewFIFO(),
	}
	for i := 0; i < cap(ret.sema); i++ {
		ret.sema <- struct{}{}
	}
	que := ret.queue
	ret.obs = observer.NewObserver(func(ev observer.EventType) {
		_ = que.Put(ev)
	}, false, Ask2ResolveDomainAddresses{})
	ret.agentSubj.ObserversAttach(ret.obs)
	return &ret
}

// Close -
func (rf *DnsRefresher) Close() error {
	rf.closeOnce.Do(func() {
		close(rf.close)
		rf.agentSubj.ObserversDetach(rf.obs)
		_ = rf.obs.Close()
		_ = rf.queue.Close()
	})
	return nil
}

// Run -
func (rf *DnsRefresher) Run(ctx context.Context) (err error) {
	type fqdn2timer = struct {
		sync.Mutex
		dict.RBDict[Ask2ResolveDomainAddresses, *time.Timer]
	}

	log := logger.FromContext(ctx).Named("dns").Named("refresher")
	log.Info("start")
	defer log.Info("stop")
	var activeQueries fqdn2timer

	defer func() {
		activeQueries.Lock()
		activeQueries.Iterate(func(_ Ask2ResolveDomainAddresses, v *time.Timer) bool {
			_ = v.Stop()
			return true
		})
		activeQueries.Unlock()
	}()
	for events := rf.queue.Reader(); ; {
		select {
		case <-ctx.Done():
			log.Info("will exit cause parent context has canceled")
			return ctx.Err()
		case raw, ok := <-events:
			if !ok {
				log.Infof("will exit cause it has closed")
				return nil
			}
			switch ev := raw.(type) {
			case DomainAddresses:
				log1 := log.WithField("domain", ev.FQDN).WithField("ip-v", ev.IpVersion)
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
						"ip-v", ev.IpVersion,
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
							rf.queue.Put(ret)
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
