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
	DnsRefresher struct{}
)

// Run -
func (rf *DnsRefresher) Run(ctx context.Context) {
	type fqdn2timer = struct {
		sync.Mutex
		dict.RBDict[Ask2ResolveDomainAddresses, *time.Timer]
	}
	var activeQueries fqdn2timer
	defer activeQueries.Iterate(func(_ Ask2ResolveDomainAddresses, v *time.Timer) bool {
		_ = v.Stop()
		return true
	})
	const semaphoreCap = 7
	sema := make(chan struct{}, semaphoreCap)
	for i := 0; i < semaphoreCap; i++ {
		sema <- struct{}{}
	}
	que := queue.NewFIFO()
	defer que.Close()
	obs := observer.NewObserver(func(ev observer.EventType) {
		_ = que.Put(ev)
	}, false, Ask2ResolveDomainAddresses{})
	agentSubj := internal.AgentSubject()
	defer agentSubj.ObserversDetach(obs)
	agentSubj.ObserversAttach(obs)

	log := logger.FromContext(ctx).Named("dns").Named("refresher")
	log.Info("start")
	defer log.Info("stop")
	for events := que.Reader(); ; {
		select {
		case <-ctx.Done():
			log.Info("will exit cause parent context has canceled")
			return
		case raw, ok := <-events:
			if !ok {
				log.Infof("will exit cause it has closed")
				return
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
				agentSubj.Notify(ev)
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
						case <-sema:
							defer func() {
								sema <- struct{}{}
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
